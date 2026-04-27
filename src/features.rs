use crate::events::{EventType, KeystrokeEvent};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const BACKSPACE: u32 = 14; // Linux evdev key code for backspace
const DELETE: u32 = 111; // Linux evdev key code for delete

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureVector {
    pub dwell_times: Vec<f64>,
    pub flight_times: Vec<f64>,
    pub digraph_latencies: HashMap<u64, f64>,
    pub wpm: f64,
    pub speed_variance: f64,
    pub error_rate: f64,
    pub immediate_correction_rate: f64,
    pub deliberate_correction_rate: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeatureName {
    MeanDwellTime,
    StdDwellTime,
    MeanFlightTime,
    StdFlightTime,
    Wpm,
    SpeedVariance,
    ErrorRate,
    ImmediateCorrectionRate,
    DeliberateCorrectionRate,
}

impl FeatureVector {
    pub fn to_vec(&self) -> Vec<f64> {
        let mean_dwell = mean(&self.dwell_times);
        let std_dwell = stddev(&self.dwell_times);
        let mean_flight = mean(&self.flight_times);
        let std_flight = stddev(&self.flight_times);
        vec![
            mean_dwell,
            std_dwell,
            mean_flight,
            std_flight,
            self.wpm,
            self.speed_variance,
            self.error_rate,
            self.immediate_correction_rate,
            self.deliberate_correction_rate,
        ]
    }
}

fn mean(v: &[f64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.iter().sum::<f64>() / v.len() as f64
}

fn stddev(v: &[f64]) -> f64 {
    if v.len() < 2 {
        return 0.0;
    }
    let m = mean(v);
    let variance = v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / (v.len() - 1) as f64;
    variance.sqrt()
}

fn digraph_key(a: u32, b: u32) -> u64 {
    ((a as u64) << 32) | (b as u64)
}

pub struct FeatureExtractor;

impl FeatureExtractor {
    pub fn extract(events: &[KeystrokeEvent]) -> FeatureVector {
        // Pre-allocate based on expected number of key-down events (~half the slice)
        let cap = (events.len() / 2).max(8);
        let mut dwell_times = Vec::with_capacity(cap);
        let mut flight_times = Vec::with_capacity(cap);
        // Cap digraph map at 256 unique bigrams to bound memory for huge windows
        let mut digraph_latencies: HashMap<u64, f64> = HashMap::with_capacity(cap.min(256));

        // Track key down times per key code — rarely more than ~10 simultaneous
        let mut key_down_times: HashMap<u32, u64> = HashMap::with_capacity(16);
        // Track last key up event
        let mut last_key_up: Option<(u32, u64)> = None;
        // For digraph: last key down
        let mut last_key_down: Option<(u32, u64)> = None;

        let mut total_keys = 0u32;
        let mut error_keys = 0u32;
        let mut immediate_corrections = 0u32;
        let mut deliberate_corrections = 0u32;

        let mut inter_key_intervals: Vec<f64> = Vec::with_capacity(cap);

        for event in events {
            match event.event_type {
                EventType::KeyDown => {
                    total_keys += 1;

                    // Check correction timing
                    if event.key_code == BACKSPACE || event.key_code == DELETE {
                        error_keys += 1;
                        // Check timing relative to last key down
                        if let Some((_, last_ts)) = last_key_down {
                            let delta_ms =
                                (event.timestamp_ns.saturating_sub(last_ts)) as f64 / 1_000_000.0;
                            if delta_ms < 200.0 {
                                immediate_corrections += 1;
                            } else if delta_ms > 500.0 {
                                deliberate_corrections += 1;
                            }
                        }
                    }

                    // Flight time: time from last key up to this key down
                    if let Some((_, up_ts)) = last_key_up {
                        let flight_ms =
                            (event.timestamp_ns.saturating_sub(up_ts)) as f64 / 1_000_000.0;
                        if (0.0..2000.0).contains(&flight_ms) {
                            flight_times.push(flight_ms);
                        }
                    }

                    // Inter-key interval: time between consecutive key downs
                    if let Some((_, last_down_ts)) = last_key_down {
                        let interval_ms =
                            (event.timestamp_ns.saturating_sub(last_down_ts)) as f64 / 1_000_000.0;
                        if (0.0..2000.0).contains(&interval_ms) {
                            inter_key_intervals.push(interval_ms);
                        }
                    }

                    // Digraph: time between consecutive key down events
                    if let Some((prev_code, prev_ts)) = last_key_down {
                        let latency_ms =
                            (event.timestamp_ns.saturating_sub(prev_ts)) as f64 / 1_000_000.0;
                        if (0.0..2000.0).contains(&latency_ms) {
                            digraph_latencies
                                .insert(digraph_key(prev_code, event.key_code), latency_ms);
                        }
                    }

                    key_down_times.insert(event.key_code, event.timestamp_ns);
                    last_key_down = Some((event.key_code, event.timestamp_ns));
                }
                EventType::KeyUp => {
                    if let Some(&down_ts) = key_down_times.get(&event.key_code) {
                        let dwell_ms =
                            (event.timestamp_ns.saturating_sub(down_ts)) as f64 / 1_000_000.0;
                        if (0.0..1000.0).contains(&dwell_ms) {
                            dwell_times.push(dwell_ms);
                        }
                        key_down_times.remove(&event.key_code);
                    }
                    last_key_up = Some((event.key_code, event.timestamp_ns));
                }
            }
        }

        // WPM calculation: use duration of window
        let wpm = if events.len() >= 2 {
            let first_ts = events.first().map(|e| e.timestamp_ns).unwrap_or(0);
            let last_ts = events.last().map(|e| e.timestamp_ns).unwrap_or(0);
            let duration_min = (last_ts.saturating_sub(first_ts)) as f64 / 1_000_000_000.0 / 60.0;
            if duration_min > 0.0 {
                (total_keys as f64 / 5.0) / duration_min
            } else {
                0.0
            }
        } else {
            0.0
        };

        let speed_variance = stddev(&inter_key_intervals);
        let error_rate = if total_keys > 0 {
            error_keys as f64 / total_keys as f64
        } else {
            0.0
        };
        let immediate_correction_rate = if error_keys > 0 {
            immediate_corrections as f64 / error_keys as f64
        } else {
            0.0
        };
        let deliberate_correction_rate = if error_keys > 0 {
            deliberate_corrections as f64 / error_keys as f64
        } else {
            0.0
        };

        FeatureVector {
            dwell_times,
            flight_times,
            digraph_latencies,
            wpm,
            speed_variance,
            error_rate,
            immediate_correction_rate,
            deliberate_correction_rate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventType;
    use proptest::prelude::*;
    use uuid::Uuid;

    fn make_event(key_code: u32, event_type: EventType, timestamp_ns: u64) -> KeystrokeEvent {
        KeystrokeEvent {
            key_code,
            event_type,
            timestamp_ns,
            session_id: Uuid::nil(),
        }
    }

    #[test]
    fn test_dwell_time_basic() {
        let events = vec![
            make_event(30, EventType::KeyDown, 0),
            make_event(30, EventType::KeyUp, 100_000_000), // 100ms dwell
        ];
        let fv = FeatureExtractor::extract(&events);
        assert_eq!(fv.dwell_times.len(), 1);
        assert!((fv.dwell_times[0] - 100.0).abs() < 0.1);
    }

    #[test]
    fn test_flight_time_basic() {
        let events = vec![
            make_event(30, EventType::KeyDown, 0),
            make_event(30, EventType::KeyUp, 50_000_000),
            make_event(31, EventType::KeyDown, 100_000_000), // 50ms flight
        ];
        let fv = FeatureExtractor::extract(&events);
        assert_eq!(fv.flight_times.len(), 1);
        assert!((fv.flight_times[0] - 50.0).abs() < 0.1);
    }

    #[test]
    fn test_error_rate() {
        let events = vec![
            make_event(30, EventType::KeyDown, 0),
            make_event(30, EventType::KeyUp, 50_000_000),
            make_event(BACKSPACE, EventType::KeyDown, 100_000_000),
            make_event(BACKSPACE, EventType::KeyUp, 150_000_000),
        ];
        let fv = FeatureExtractor::extract(&events);
        assert!((fv.error_rate - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_to_vec_length() {
        let fv = FeatureVector {
            dwell_times: vec![100.0, 120.0],
            flight_times: vec![50.0],
            digraph_latencies: HashMap::new(),
            wpm: 60.0,
            speed_variance: 10.0,
            error_rate: 0.05,
            immediate_correction_rate: 0.3,
            deliberate_correction_rate: 0.2,
        };
        assert_eq!(fv.to_vec().len(), 9);
    }

    #[test]
    fn test_digraph_latencies_populated() {
        // Two consecutive key-down events produce one digraph entry
        let events = vec![
            make_event(30, EventType::KeyDown, 0),
            make_event(30, EventType::KeyUp, 30_000_000),
            make_event(31, EventType::KeyDown, 50_000_000),
            make_event(31, EventType::KeyUp, 80_000_000),
        ];
        let fv = FeatureExtractor::extract(&events);
        let key = digraph_key(30, 31);
        assert!(fv.digraph_latencies.contains_key(&key));
        // Latency = (50 - 0) ms = 50 ms
        assert!((fv.digraph_latencies[&key] - 50.0).abs() < 0.1);
    }

    #[test]
    fn test_immediate_and_deliberate_correction_rates() {
        let events = vec![
            make_event(30, EventType::KeyDown, 0),
            make_event(30, EventType::KeyUp, 30_000_000),
            // immediate correction (< 200ms)
            make_event(BACKSPACE, EventType::KeyDown, 100_000_000),
            make_event(BACKSPACE, EventType::KeyUp, 130_000_000),
            make_event(31, EventType::KeyDown, 1_000_000_000),
            make_event(31, EventType::KeyUp, 1_030_000_000),
            // deliberate correction (> 500ms)
            make_event(DELETE, EventType::KeyDown, 1_700_000_000),
            make_event(DELETE, EventType::KeyUp, 1_730_000_000),
        ];

        let fv = FeatureExtractor::extract(&events);
        assert!((fv.error_rate - 0.5).abs() < 0.01);
        assert!((fv.immediate_correction_rate - 0.5).abs() < 0.01);
        assert!((fv.deliberate_correction_rate - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_outlier_intervals_are_filtered() {
        let events = vec![
            make_event(30, EventType::KeyDown, 0),
            make_event(30, EventType::KeyUp, 2_500_000_000), // 2500ms dwell -> filtered
            make_event(31, EventType::KeyDown, 5_100_000_000), // 2600ms flight -> filtered
        ];

        let fv = FeatureExtractor::extract(&events);
        assert!(fv.dwell_times.is_empty());
        assert!(fv.flight_times.is_empty());
    }

    proptest! {
        #[test]
        fn test_feature_extraction_no_panic(
            n in 0usize..50,
        ) {
            let session_id = Uuid::nil();
            let mut events = Vec::new();
            for i in 0..n {
                let ts = (i as u64) * 100_000_000;
                events.push(KeystrokeEvent {
                    key_code: 30,
                    event_type: EventType::KeyDown,
                    timestamp_ns: ts,
                    session_id,
                });
                events.push(KeystrokeEvent {
                    key_code: 30,
                    event_type: EventType::KeyUp,
                    timestamp_ns: ts + 50_000_000,
                    session_id,
                });
            }
            let fv = FeatureExtractor::extract(&events);
            let vec = fv.to_vec();
            // All values must be finite
            for v in &vec {
                prop_assert!(v.is_finite(), "Non-finite value: {}", v);
            }
        }
    }
}
