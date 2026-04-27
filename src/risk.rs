use crate::baseline::BaselineProfile;
use crate::features::FeatureName;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskEvent {
    pub session_id: Uuid,
    pub timestamp_utc: String,
    pub risk_score: u8,
    pub confidence: f32,
    pub anomalous_features: Vec<FeatureName>,
    pub window_keystrokes: u32,
    pub model_version: String,
}

pub struct RiskScorer {
    pub threshold: f64,
    pub k: f64,
}

impl RiskScorer {
    pub fn new(threshold: f64, k: f64) -> Self {
        Self { threshold, k }
    }

    pub fn score(
        &self,
        session_id: Uuid,
        features: &[f64],
        baseline: &BaselineProfile,
        window_keystrokes: u32,
    ) -> RiskEvent {
        let distance =
            mahalanobis_distance(features, &baseline.feature_means, &baseline.feature_stds);
        let risk_raw = sigmoid(self.k * (distance - self.threshold)) * 100.0;
        let risk_score = risk_raw.clamp(0.0, 100.0) as u8;

        let confidence = if baseline.enrollment_count > 0 {
            ((window_keystrokes as f64) / (baseline.enrollment_count as f64)).min(1.0) as f32
        } else {
            0.0f32
        };

        let anomalous_features = find_anomalous_features(features, baseline);

        RiskEvent {
            session_id,
            timestamp_utc: Utc::now().to_rfc3339(),
            risk_score,
            confidence,
            anomalous_features,
            window_keystrokes,
            model_version: "1.0.0".to_string(),
        }
    }
}

fn mahalanobis_distance(features: &[f64], means: &[f64], stds: &[f64]) -> f64 {
    let sum: f64 = features
        .iter()
        .zip(means.iter())
        .zip(stds.iter())
        .map(|((x, mu), sigma)| {
            let s = sigma.max(1e-9);
            ((x - mu) / s).powi(2)
        })
        .sum();
    sum.sqrt()
}

fn sigmoid(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}

fn find_anomalous_features(features: &[f64], baseline: &BaselineProfile) -> Vec<FeatureName> {
    let names = FeatureName::all();
    let mut anomalous = Vec::new();
    for (i, ((&x, &mu), &sigma)) in features
        .iter()
        .zip(baseline.feature_means.iter())
        .zip(baseline.feature_stds.iter())
        .enumerate()
    {
        let s = sigma.max(1e-9);
        let z = ((x - mu) / s).abs();
        if z > 2.0 {
            if let Some(name) = names.get(i) {
                anomalous.push(name.clone());
            }
        }
    }
    anomalous
}

impl FeatureName {
    pub fn all() -> Vec<FeatureName> {
        vec![
            FeatureName::MeanDwellTime,
            FeatureName::StdDwellTime,
            FeatureName::MeanFlightTime,
            FeatureName::StdFlightTime,
            FeatureName::Wpm,
            FeatureName::SpeedVariance,
            FeatureName::ErrorRate,
            FeatureName::ImmediateCorrectionRate,
            FeatureName::DeliberateCorrectionRate,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::BaselineProfile;

    #[test]
    fn test_risk_score_identical_features() {
        let mut profile = BaselineProfile::new(9, 0.05);
        // Warm up profile with consistent values
        for _ in 0..100 {
            profile.update(&[100.0, 10.0, 50.0, 5.0, 60.0, 8.0, 0.05, 0.3, 0.2], 50);
        }
        let scorer = RiskScorer::new(5.0, 1.0);
        // Using the same values should give low distance
        let event = scorer.score(
            Uuid::new_v4(),
            &[100.0, 10.0, 50.0, 5.0, 60.0, 8.0, 0.05, 0.3, 0.2],
            &profile,
            50,
        );
        // Identical features should yield low risk score
        assert!(
            event.risk_score < 50,
            "Expected low risk but got {}",
            event.risk_score
        );
    }

    #[test]
    fn test_risk_score_extreme_anomaly() {
        let mut profile = BaselineProfile::new(9, 0.05);
        for _ in 0..100 {
            profile.update(&[100.0, 10.0, 50.0, 5.0, 60.0, 8.0, 0.05, 0.3, 0.2], 50);
        }
        let scorer = RiskScorer::new(2.0, 1.0);
        // Completely different features
        let event = scorer.score(
            Uuid::new_v4(),
            &[1000.0, 500.0, 1000.0, 200.0, 5.0, 300.0, 0.9, 0.9, 0.9],
            &profile,
            50,
        );
        assert!(
            event.risk_score > 50,
            "Expected high risk but got {}",
            event.risk_score
        );
    }

    #[test]
    fn test_sigmoid_range() {
        for x in [-10.0, -1.0, 0.0, 1.0, 10.0] {
            let s = sigmoid(x);
            assert!((0.0..=1.0).contains(&s));
        }
    }

    #[test]
    fn test_mahalanobis_zero() {
        let features = vec![1.0, 2.0, 3.0];
        let means = vec![1.0, 2.0, 3.0];
        let stds = vec![1.0, 1.0, 1.0];
        let dist = mahalanobis_distance(&features, &means, &stds);
        assert!(dist.abs() < 1e-9);
    }

    #[test]
    fn test_anomalous_features_detected() {
        let mut profile = BaselineProfile::new(9, 0.05);
        for _ in 0..200 {
            profile.update(&[100.0, 10.0, 50.0, 5.0, 60.0, 8.0, 0.05, 0.3, 0.2], 50);
        }

        let scorer = RiskScorer::new(2.0, 1.0);
        let event = scorer.score(
            Uuid::new_v4(),
            &[100.0, 10.0, 50.0, 5.0, 260.0, 8.0, 0.05, 0.3, 0.2],
            &profile,
            50,
        );

        assert!(event.anomalous_features.contains(&FeatureName::Wpm));
    }
}
