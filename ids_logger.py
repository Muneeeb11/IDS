import logging
import os
from datetime import datetime

class IDSLogger:
    """Central logger for model status, predictions, and performance messages."""

    def __init__(self, log_dir=None):
        if log_dir is None:
            log_dir = os.environ.get("IDS_LOG_DIR", "logs")

        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        # Setup logging
        log_file = os.path.join(log_dir, f"ids_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding="utf-8"),  # Fix unicode crash
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger('IDS')
        
    def log_model_load(self, success, message=""):
        if success:
            self.logger.info(f"✅ Model loaded successfully: {message}")
        else:
            self.logger.error(f"❌ Model load failed: {message}")
    
    def log_prediction(self, packet_info, prediction, confidence=None):
        """
        Logs IDS predictions with confidence.
        
        prediction: str OR tuple (label, confidence)
        confidence: optional float value between 0–100 or 0–1
        """
        # If prediction is a tuple, unpack it
        if isinstance(prediction, (tuple, list)) and len(prediction) == 2:
            prediction, confidence = prediction  # unpack label and confidence

        # Normalize confidence
        if confidence is None:
            confidence_pct = "N/A"
        else:
            # Convert 0–1 to % if needed
            if confidence <= 1:
                confidence_pct = round(confidence * 100, 1)
            else:
                confidence_pct = round(confidence, 1)
        
        src = packet_info.get("source", "Unknown")
        dst = packet_info.get("destination", "Unknown")

        if prediction != "Benign":
            self.logger.warning(
                f"🚨 THREAT DETECTED: {prediction} | "
                f"Confidence: {confidence_pct}% | "
                f"Source: {src} | Dest: {dst}"
            )
        else:
            self.logger.info(
                f"✅ Benign traffic ({confidence_pct}% confidence): "
                f"{src} -> {dst}"
            )

    
    def log_performance(self, packets_processed, avg_processing_time):
        self.logger.info(
            f"📊 Performance: {packets_processed} packets, "
            f"Avg time: {avg_processing_time:.4f}s"
        )


# Global instance
logger = IDSLogger()

