import sys
import os
import time
import threading
from datetime import datetime
from collections import deque

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QTableWidget, QTableWidgetItem, QTextEdit, 
                             QComboBox, QLineEdit, QLabel, QSplitter, QTabWidget,
                             QProgressBar, QGroupBox, QCheckBox, QSpinBox, QFileDialog,
                             QMessageBox, QHeaderView, QTreeWidget, QTreeWidgetItem)
from PyQt5.QtCore import QTimer, Qt, pyqtSignal, QObject
from PyQt5.QtGui import QFont, QColor, QBrush

from packet_sniffer import PacketSniffer, get_network_interfaces
from async_predictor import AsyncPredictor
from ids_logger import logger

class PacketSignal(QObject):
    """Thread-safe signals used to update PyQt widgets from worker threads."""

    packet_received = pyqtSignal(dict)
    stats_updated = pyqtSignal(dict)
    attack_detected = pyqtSignal(dict)
    performance_updated = pyqtSignal(dict)
    capture_error = pyqtSignal(str)

class OptimizedPacketSnifferGUI(QMainWindow):
    """Main desktop application for live capture and IDS monitoring."""

    def __init__(self):
        super().__init__()
        self.sniffer = None
        self.ids_model = None
        self.async_predictor = None
        self.signal = PacketSignal()
        
        # Performance tracking
        self.packets_received = 0
        self.packets_processed = 0
        self.attack_counter = 0
        self.packet_buffer = deque(maxlen=1000)  # Limit memory usage
        self.last_update_time = time.time()
        
        self.setup_ui()
        self.setup_sniffer()
        self.load_ids_model()
        
    def load_ids_model(self):
        """Load the saved hybrid IDS model and start the prediction worker."""
 
        try:
            print("🔄 Loading IDS model...")
            
            # Get the parent directory (IDS folder)
            current_dir = os.path.dirname(os.path.abspath(__file__))  # Tool folder
            parent_dir = os.path.dirname(current_dir)  # IDS folder
            scripts_dir = os.path.join(parent_dir, 'scripts')
            models_dir = os.path.join(parent_dir, 'models')
            
            print(f"📁 Current: {current_dir}")
            print(f"📁 Parent: {parent_dir}")
            print(f"📁 Scripts: {scripts_dir}")
            print(f"📁 Models: {models_dir}")
            
            # Add both directories to Python path
            if scripts_dir not in sys.path:
                sys.path.insert(0, scripts_dir)
            if models_dir not in sys.path:
                sys.path.insert(0, models_dir)
            if parent_dir not in sys.path:
                sys.path.insert(0, parent_dir)
                
            print(f"✅ Python path updated")
            
            # Check if files exist
            hybrid_model_path = os.path.join(scripts_dir, 'hybrid_model.py')
            model_file_path = os.path.join(models_dir, 'hybrid_dl_ml_model.pkl')
            
            print(f"🔍 Looking for hybrid_model.py: {os.path.exists(hybrid_model_path)}")
            print(f"🔍 Looking for model file: {os.path.exists(model_file_path)}")
            
            if not os.path.exists(hybrid_model_path):
                raise FileNotFoundError(f"hybrid_model.py not found at: {hybrid_model_path}")
            if not os.path.exists(model_file_path):
                raise FileNotFoundError(f"Model file not found at: {model_file_path}")
            
            # Import using absolute path
            import importlib.util
            spec = importlib.util.spec_from_file_location("hybrid_model", hybrid_model_path)
            hybrid_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(hybrid_module)
            MemoryEfficientHybridDLMLModel = hybrid_module.MemoryEfficientHybridDLMLModel
            
            print("✅ Successfully imported hybrid_model")
            
            # Load the model
            self.ids_model = MemoryEfficientHybridDLMLModel.load(model_file_path)
            
            # Initialize async predictor
            self.async_predictor = AsyncPredictor(self.ids_model, batch_size=5)
            self.async_predictor.start()
            
            print("✅ IDS: Model loaded successfully")
            self.statusBar().showMessage("✅ IDS: Model loaded - Real-time protection ENABLED")
            
        except Exception as e:
            print(f"❌ Model load failed: {e}")
            import traceback
            print("Detailed traceback:")
            print(traceback.format_exc())
            self.statusBar().showMessage("❌ IDS: Model load failed - Running in basic mode")
    
            try:
                # Try different possible model paths
                possible_paths = [
                    "../models/hybrid_dl_ml_model.pkl",  # Relative path from scripts folder
                    "models/hybrid_dl_ml_model.pkl",     # Relative path from current directory
                    "./models/hybrid_dl_ml_model.pkl",   # Explicit relative path
                    "hybrid_dl_ml_model.pkl"             # Same directory
                ]
                
                model_path = None
                for path in possible_paths:
                    if os.path.exists(path):
                        model_path = path
                        break
                
                if not model_path:
                    logger.log_model_load(False, "Model file not found in any expected location")
                    self.statusBar().showMessage("❌ IDS: Model file not found")
                    return

                logger.logger.info(f"Found model at: {model_path}")
                
                # Add parent directory to Python path for imports
                parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                if parent_dir not in sys.path:
                    sys.path.insert(0, parent_dir)
                
                # Try to import from different locations
                try:
                    from hybrid_model import MemoryEfficientHybridDLMLModel
                    model_class = MemoryEfficientHybridDLMLModel
                except ImportError:
                    # Try importing from scripts folder
                    scripts_dir = os.path.join(parent_dir, 'scripts')
                    if scripts_dir not in sys.path:
                        sys.path.insert(0, scripts_dir)
                    from hybrid_model import MemoryEfficientHybridDLMLModel
                    model_class = MemoryEfficientHybridDLMLModel

                # Load the model
                self.ids_model = model_class.load(model_path)
                
                # Initialize async predictor
                self.async_predictor = AsyncPredictor(self.ids_model, batch_size=5)
                self.async_predictor.start()
                
                logger.log_model_load(True, f"Hybrid model loaded from {model_path}")
                self.statusBar().showMessage("✅ IDS: Model loaded successfully")
                
            except Exception as e:
                logger.log_model_load(False, str(e))
                self.statusBar().showMessage(f"❌ IDS: Model load failed: {e}")
                # Print detailed error for debugging
                import traceback
                print("Detailed error:", traceback.format_exc())
                """Load the trained hybrid IDS model with proper logging"""
                try:
                    model_path = "../models/hybrid_dl_ml_model.pkl"
                    if os.path.exists(model_path):
                        from hybrid_model import MemoryEfficientHybridDLMLModel
                        self.ids_model = MemoryEfficientHybridDLMLModel.load(model_path)
                        
                        # Initialize async predictor
                        self.async_predictor = AsyncPredictor(self.ids_model, batch_size=5)
                        self.async_predictor.start()
                        
                        logger.log_model_load(True, "Hybrid model with async processing")
                        self.statusBar().showMessage("✅ IDS: Model loaded with async processing")
                        
                    else:
                        logger.log_model_load(False, f"Model file not found: {model_path}")
                        self.statusBar().showMessage("❌ IDS: Model file not found")
                        
                except Exception as e:
                    logger.log_model_load(False, str(e))
                    self.statusBar().showMessage(f"❌ IDS: Model load failed: {e}")
            
    
    
   
   
    def setup_ui(self):
        """Setup the main GUI"""
        self.setWindowTitle("Optimized IDS Sniffer  - Real-time Threat Detection")
        self.setGeometry(100, 100, 1600, 1000)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Control panel
        self.setup_control_panel(layout)
        
        # Main content area
        splitter = QSplitter(Qt.Vertical)
        layout.addWidget(splitter)
        
        # Packet table
        self.setup_packet_table(splitter)
        
        # Details area
        self.setup_details_area(splitter)
        
        splitter.setSizes([500, 400])
        self.setup_status_bar()
        
    def setup_control_panel(self, layout):
        """Setup optimized control panel"""
        control_group = QGroupBox("Capture Controls & IDS Settings")
        control_layout = QVBoxLayout(control_group)
        
        # First row
        basic_layout = QHBoxLayout()
        basic_layout.addWidget(QLabel("Interface:"))
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(get_network_interfaces())
        basic_layout.addWidget(self.interface_combo)
        
        basic_layout.addWidget(QLabel("Filter:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("tcp, udp, port 80")
        self.filter_edit.setMinimumWidth(150)
        basic_layout.addWidget(self.filter_edit)
        
        # Performance settings
        basic_layout.addWidget(QLabel("Speed:"))
        self.speed_combo = QComboBox()
        self.speed_combo.addItems(["Fast", "Balanced", "Detailed"])
        self.speed_combo.setCurrentIndex(1)
        basic_layout.addWidget(self.speed_combo)
        
        basic_layout.addStretch()
        
        # Second row
        ids_layout = QHBoxLayout()
        self.ids_enabled = QCheckBox("Enable Real-time IDS Protection")
        self.ids_enabled.setChecked(True)
        ids_layout.addWidget(self.ids_enabled)
        
        # Performance monitor
        self.performance_label = QLabel("Performance: Ready")
        self.performance_label.setStyleSheet("QLabel { color: blue; font-weight: bold; }")
        ids_layout.addWidget(self.performance_label)
        
        ids_layout.addStretch()
        
        # Buttons
        self.start_btn = QPushButton("▶ Start Capture")
        self.start_btn.clicked.connect(self.start_capture)
        self.start_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; padding: 8px; }")
        ids_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("⏹ Stop")
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("QPushButton { background-color: #f44336; color: white; padding: 8px; }")
        ids_layout.addWidget(self.stop_btn)
        
        self.clear_btn = QPushButton("🗑 Clear")
        self.clear_btn.clicked.connect(self.clear_packets)
        self.clear_btn.setStyleSheet("QPushButton { background-color: #ff9800; color: white; padding: 8px; }")
        ids_layout.addWidget(self.clear_btn)
        
        control_layout.addLayout(basic_layout)
        control_layout.addLayout(ids_layout)
        layout.addWidget(control_group)
        
    def setup_packet_table(self, splitter):
        """Setup optimized packet table"""
        table_widget = QWidget()
        table_layout = QVBoxLayout(table_widget)
        
        # Real-time stats
        stats_layout = QHBoxLayout()
        self.stats_labels = {
            'packets': QLabel("📦 Received: 0"),
            'processed': QLabel("⚡ Processed: 0"), 
            'attacks': QLabel("🚨 Attacks: 0"),
            'queue': QLabel("📊 Queue: 0"),
            'speed': QLabel("⏱ Speed: 0 pkt/s")
        }
        
        # Style stats labels
        for label in self.stats_labels.values():
            label.setStyleSheet("QLabel { font-weight: bold; padding: 5px; }")
            stats_layout.addWidget(label)
        stats_layout.addStretch()
        
        table_layout.addLayout(stats_layout)
        
        # Packet table
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(7)
        self.packet_table.setHorizontalHeaderLabels([
            "Time", "Source", "Destination", "Protocol", "Length", "Info", "Threat"
        ])
        
        # Optimize table performance
        self.packet_table.setAlternatingRowColors(True)
        self.packet_table.setSortingEnabled(False)  # Disable sorting for performance
        self.packet_table.setShowGrid(False)
        self.packet_table.setWordWrap(False)
        
        header = self.packet_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Time
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Source
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Destination
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Protocol
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Length
        header.setSectionResizeMode(5, QHeaderView.Stretch)           # Info
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)  # Threat
        
        self.packet_table.clicked.connect(self.show_packet_details)
        table_layout.addWidget(self.packet_table)
        
        splitter.addWidget(table_widget)
        
    def setup_details_area(self, splitter):
        """Setup details area with log viewer"""
        tabs = QTabWidget()
        
        # Log viewer
        self.log_text = QTextEdit()
        self.log_text.setFont(QFont("Courier", 9))
        self.log_text.setReadOnly(True)
        tabs.addTab(self.log_text, "📋 Live Log")
        
        # Packet details
        self.details_tree = QTreeWidget()
        self.details_tree.setHeaderLabels(["Field", "Value"])
        tabs.addTab(self.details_tree, "📄 Packet Details")
        
        # Performance monitor
        self.performance_text = QTextEdit()
        self.performance_text.setReadOnly(True)
        self.performance_text.setFont(QFont("Arial", 10))
        tabs.addTab(self.performance_text, "📊 Performance")
        
        splitter.addWidget(tabs)
        
    def setup_status_bar(self):
        """Setup status bar with performance info"""
        self.statusBar().showMessage("🚀 Ready - Optimized IDS Sniffer with Real-time Threat Detection")
        
        # Setup timers
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_display)
        self.update_timer.start(500)  # Fast updates for smooth UI
        
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats)
        self.stats_timer.start(1000)  # Stats every second
        
        self.log_timer = QTimer()
        self.log_timer.timeout.connect(self.update_logs)
        self.log_timer.start(500)  # Log updates every 500ms
        
    def setup_sniffer(self):
        """Setup packet sniffer"""
        self.sniffer = PacketSniffer()
        self.sniffer.add_packet_callback(self.on_packet_received)
        self.sniffer.add_error_callback(self.on_capture_error)
        
        # Connect signals
        self.signal.packet_received.connect(self.add_packet_to_table)
        self.signal.attack_detected.connect(self.on_attack_detected)
        self.signal.capture_error.connect(self.handle_capture_error)
        
    def on_packet_received(self, packet):
        """Handle incoming packets without blocking packet capture."""
        self.packets_received += 1
        
        # Add to buffer for display
        self.packet_buffer.append(packet)
        
        # Prediction is intentionally asynchronous. The sniffer thread should
        # never wait for TensorFlow or scikit-learn to finish a prediction.
        if self.ids_enabled.isChecked() and self.async_predictor:
            if not self.async_predictor.add_packet(packet):
                # Queue full, packet dropped to prevent lag
                pass
        
        # Emit signal for UI update (fast, non-blocking)
        self.signal.packet_received.emit(packet)

    def on_capture_error(self, message):
        """Forward sniffer thread errors to the UI thread."""
        self.signal.capture_error.emit(message)

    def handle_capture_error(self, message):
        """Show capture errors in the GUI instead of only printing to terminal."""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        if "could not open /dev/bpf" in message or "Operation not permitted" in message:
            guidance = (
                "macOS blocked packet capture. Relaunch this app with sudo/root "
                "permissions, then choose the active interface, usually en0."
            )
        else:
            guidance = "Check the selected interface and capture filter, then try again."

        self.statusBar().showMessage(f"Capture failed: {message}")
        logger.logger.error(f"❌ Capture failed: {message}")
        QMessageBox.critical(self, "Packet Capture Failed", f"{message}\n\n{guidance}")
    
    def on_attack_detected(self, packet):
        """Handle detected attacks"""
        self.attack_counter += 1
        #logger.logger.warning(f"🚨 Attack #{self.attack_counter}: {packet['threat_level']}")
        
        # Show alert for serious attacks
        if packet['threat_level'] in ['DDoS', 'DoS']:
            self.show_attack_alert(packet)
    
    def show_attack_alert(self, packet):
        """Show popup alert for serious attacks"""
        alert_msg = f"""
        🚨 CRITICAL SECURITY ALERT 🚨
        
        Attack Type: {packet['threat_level']}
        Source: {packet.get('source', 'Unknown')}
        Destination: {packet.get('destination', 'Unknown')}
        Time: {packet.get('time_str', 'Unknown')}
        
        Immediate investigation required!
        """
        
        QMessageBox.critical(self, "🚨 IDS CRITICAL ALERT", alert_msg)
    
    def add_packet_to_table(self, packet):
        """Add packet to table - OPTIMIZED"""
        # Limit table size for performance
        if self.packet_table.rowCount() > 500:
            self.packet_table.removeRow(0)
            
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        
        # Add basic info (fast)
        self.packet_table.setItem(row, 0, QTableWidgetItem(packet['time_str'][-12:]))  # Time only
        self.packet_table.setItem(row, 1, QTableWidgetItem(packet['source']))
        self.packet_table.setItem(row, 2, QTableWidgetItem(packet['destination']))
        
        # Protocol with color
        protocol_item = QTableWidgetItem(packet['protocol'])
        self.color_protocol_item(protocol_item, packet['protocol'])
        self.packet_table.setItem(row, 3, protocol_item)
        
        self.packet_table.setItem(row, 4, QTableWidgetItem(str(packet['length'])))
        self.packet_table.setItem(row, 5, QTableWidgetItem(packet['info'][:50]))  # Truncate
        
        # Threat info
        threat = packet.get('threat_level', 'Analyzing...')
        threat_item = QTableWidgetItem(threat)
        self.color_threat_item(threat_item, threat)
        self.packet_table.setItem(row, 6, threat_item)
        
        # Auto-scroll to bottom occasionally (not every packet for performance)
        if row % 10 == 0:
            self.packet_table.scrollToBottom()
    
    def color_protocol_item(self, item, protocol):
        """Color code protocol items"""
        colors = {
            'TCP': QColor(144, 238, 144),  # Light green
            'UDP': QColor(135, 206, 250),  # Light sky blue
            'ICMP': QColor(255, 182, 193), # Light pink
            'ARP': QColor(255, 215, 0),    # Gold
        }
        
        if protocol in colors:
            item.setBackground(colors[protocol])
    
    def color_threat_item(self, item, threat_level):
        """Color code threat levels"""
        colors = {
            'Benign': QColor(144, 238, 144),    # Green
            'DDoS': QColor(255, 0, 0),          # Red
            'DoS': QColor(255, 69, 0),          # Orange-red
            'Mirai': QColor(255, 140, 0),       # Dark orange
            'Recon': QColor(255, 215, 0),       # Yellow
            'BruteForce': QColor(255, 165, 0),  # Orange
            'Web': QColor(218, 112, 214),       # Orchid
            'Spoofing': QColor(138, 43, 226),   # Blue violet
            'Analyzing...': QColor(200, 200, 200), # Gray
        }
        
        if threat_level in colors:
            item.setBackground(colors[threat_level])
            item.setForeground(QBrush(QColor(0, 0, 0)))  # Black text
    
    def show_packet_details(self, index):
        """Show details of selected packet"""
        row = index.row()
        if row < 0 or row >= len(self.packet_buffer):
            return
            
        # Get packet from buffer
        packet = list(self.packet_buffer)[row] if row < len(self.packet_buffer) else None
        if not packet:
            return
            
        self.display_packet_details(packet)
        self.update_performance_info()
    
    def display_packet_details(self, packet):
        """Display detailed packet information"""
        # Clear previous details
        self.details_tree.clear()
        
        # Basic info
        basic_info = QTreeWidgetItem(self.details_tree, ["Basic Information", ""])
        QTreeWidgetItem(basic_info, ["Timestamp", packet['time_str']])
        QTreeWidgetItem(basic_info, ["Source", packet['source']])
        QTreeWidgetItem(basic_info, ["Destination", packet['destination']])
        QTreeWidgetItem(basic_info, ["Protocol", packet['protocol']])
        QTreeWidgetItem(basic_info, ["Length", str(packet['length'])])
        
        # IDS Analysis if available
        if 'threat_level' in packet:
            ids_info = QTreeWidgetItem(self.details_tree, ["IDS Analysis", ""])
            QTreeWidgetItem(ids_info, ["Threat Level", packet['threat_level']])
            QTreeWidgetItem(ids_info, ["Classification", "🚨 ATTACK" if packet.get('is_attack', False) else "✅ BENIGN"])
            if packet.get('detection_reason'):
                QTreeWidgetItem(ids_info, ["Reason", packet['detection_reason']])
        
        # MAC addresses if available
        if 'src_mac' in packet:
            mac_info = QTreeWidgetItem(self.details_tree, ["Ethernet", ""])
            QTreeWidgetItem(mac_info, ["Source MAC", packet['src_mac']])
            QTreeWidgetItem(mac_info, ["Destination MAC", packet['dst_mac']])
        
        # Port information if available
        if 'sport' in packet:
            port_info = QTreeWidgetItem(self.details_tree, ["Ports", ""])
            QTreeWidgetItem(port_info, ["Source Port", str(packet['sport'])])
            QTreeWidgetItem(port_info, ["Destination Port", str(packet['dport'])])
        
        # Expand all items
        self.details_tree.expandAll()
    
    def update_display(self):
        """Update UI elements - called frequently for smooth updates"""
        current_time = time.time()

        # Update packet table with processed results
        if self.async_predictor:
            results = self.async_predictor.get_results()
            for packet in results:
                self.packets_processed += 1

                threat = packet.get('threat_level', 'Analyzing...')
                if isinstance(threat, tuple):
                    threat = str(threat[0])
                
                        # Update threat column directly in table
                for row in range(self.packet_table.rowCount()):
                    table_time = self.packet_table.item(row, 0).text()
                    if table_time == packet['time_str'][-12:]:
                        threat_item = QTableWidgetItem(threat)
                        self.color_threat_item(threat_item, threat)
                        self.packet_table.setItem(row, 6, threat_item)
                        break  # Stop after updating the matching row

                # Emit attack signal if needed
                if packet.get('is_attack', False):
                    self.signal.attack_detected.emit(packet)

        # Update packet speed
        time_diff = current_time - self.last_update_time
        if time_diff > 1.0:  # Update speed every second
            packets_since_last = self.packets_received - getattr(self, 'last_packet_count', 0)
            speed = packets_since_last / time_diff if time_diff > 0 else 0
            self.stats_labels['speed'].setText(f"⏱ Speed: {speed:.1f} pkt/s")
            self.last_packet_count = self.packets_received
            self.last_update_time = current_time

    
    def update_stats(self):
        """Update statistics display"""
        # Update stats labels
        self.stats_labels['packets'].setText(f"📦 Received: {self.packets_received}")
        self.stats_labels['processed'].setText(f"⚡ Processed: {self.packets_processed}")
        self.stats_labels['attacks'].setText(f"🚨 Attacks: {self.attack_counter}")
        
        # Update queue size
        if self.async_predictor:
            queue_size = self.async_predictor.packet_queue.qsize()
            self.stats_labels['queue'].setText(f"📊 Queue: {queue_size}")
            
            # Performance warning
            if queue_size > 50:
                self.performance_label.setText("⚠️ High Load")
                self.performance_label.setStyleSheet("QLabel { color: orange; font-weight: bold; }")
            elif queue_size > 20:
                self.performance_label.setText("⚡ Good")
                self.performance_label.setStyleSheet("QLabel { color: blue; font-weight: bold; }")
            else:
                self.performance_label.setText("✅ Optimal")
                self.performance_label.setStyleSheet("QLabel { color: green; font-weight: bold; }")
    
    def update_logs(self):
        """Update log display from logger"""
        try:
            # Read the latest log file
            log_dir = logger.log_dir
            if os.path.exists(log_dir):
                log_files = sorted([f for f in os.listdir(log_dir) if f.endswith('.log')])
                if log_files:
                    latest_log = os.path.join(log_dir, log_files[-1])
                    with open(latest_log, 'r', encoding='utf-8') as f:
                        lines = f.readlines()[-100:]  # Last 100 lines
                        self.log_text.setText(''.join(lines))
                        self.log_text.moveCursor(self.log_text.textCursor().End)
        except Exception as e:
            pass  # Silently handle log read errors
    
    def update_performance_info(self):
        """Update performance information tab"""
        if self.async_predictor:
            stats = self.async_predictor.get_stats()
            
            performance_text = f"""
🚀 IDS PERFORMANCE MONITOR
{'='*50}

📊 Processing Statistics:
• Packets Processed: {stats['packets_processed']:,}
• Threats Detected: {stats['threats_detected']:,}
• Average Processing Time: {stats['avg_processing_time']:.4f}s
• Processing Speed: {1/stats['avg_processing_time']:.1f} pkt/s (if > 0)

🎯 System Status:
• IDS Protection: {'✅ ENABLED' if self.ids_enabled.isChecked() else '❌ DISABLED'}
• Model Loaded: {'✅ YES' if self.ids_model else '❌ NO'}
• Async Processing: {'✅ ACTIVE' if self.async_predictor and self.async_predictor.is_running else '❌ INACTIVE'}

💡 Performance Tips:
• Use 'Fast' mode for high-traffic networks
• Clear packets regularly to free memory
• Monitor queue size - high values indicate system overload
• Restart if performance degrades

📈 Real-time Metrics:
• Packets Received: {self.packets_received:,}
• Packets Displayed: {self.packet_table.rowCount()}
• Current Queue: {self.async_predictor.packet_queue.qsize()}
• UI Update Rate: 10Hz (smooth)
"""
            self.performance_text.setText(performance_text)
    
    def start_capture(self):
        """Start packet capture"""
        try:
            interface = self.interface_combo.currentText()
            filter_str = self.filter_edit.text().strip() or None
            
            self.sniffer.interface = interface
            # count=0 means unlimited capture until the user clicks Stop.
            if self.sniffer.start_sniffing(filter_str, count=0):  # Unlimited
                self.start_btn.setEnabled(False)
                self.stop_btn.setEnabled(True)
                self.last_update_time = time.time()
                self.last_packet_count = 0
                
                status_msg = f"🎯 Capturing on {interface}"
                if self.ids_enabled.isChecked():
                    status_msg += " with REAL-TIME IDS PROTECTION"
                self.statusBar().showMessage(status_msg)
                
                logger.logger.info(f"🚀 Capture started on {interface} with IDS: {self.ids_enabled.isChecked()}")
            else:
                QMessageBox.warning(self, "Error", "Could not start capture. Another capture might be running.")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start capture: {str(e)}")
            logger.logger.error(f"❌ Capture start failed: {e}")
    
    def stop_capture(self):
        """Stop packet capture"""
        self.sniffer.stop_sniffing()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.statusBar().showMessage("🛑 Capture stopped")
        logger.logger.info("🛑 Capture stopped")
    
    def clear_packets(self):
        """Clear all captured packets"""
        self.sniffer.clear_packets()
        self.packet_table.setRowCount(0)
        self.packet_buffer.clear()
        self.packets_received = 0
        self.packets_processed = 0
        self.attack_counter = 0
        self.details_tree.clear()
        self.log_text.clear()
        self.statusBar().showMessage("🗑 All packets cleared")
        logger.logger.info("🗑 Packets cleared")
    
    def save_packets(self):
        """Save captured packets to file"""
        if not self.sniffer.packets:
            QMessageBox.information(self, "Save Packets", "No packets to save.")
            return
            
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Packets", f"ids_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "CSV Files (*.csv);;PCAP Files (*.pcap)"
        )
        
        if filename:
            try:
                if filename.endswith('.csv'):
                    success = self.sniffer.save_packets_to_file(filename, 'csv')
                else:
                    success = self.sniffer.save_packets_to_file(filename, 'pcap')
                    
                if success:
                    QMessageBox.information(self, "Save Packets", f"✅ Packets saved to {filename}")
                    logger.logger.info(f"💾 Packets saved to {filename}")
                else:
                    QMessageBox.warning(self, "Save Packets", "❌ Failed to save packets.")
            except Exception as e:
                QMessageBox.critical(self, "Save Packets", f"❌ Error saving packets: {str(e)}")
    
    def closeEvent(self, event):
        """Handle application closure"""
        if self.sniffer and self.sniffer.is_sniffing:
            self.sniffer.stop_sniffing()
        
        if self.async_predictor:
            self.async_predictor.stop()
        
        logger.logger.info("🔴 IDS Application closed")
        event.accept()

def main():
    app = QApplication(sys.argv)
    
    # Check if running as administrator (required for packet capture on Windows)
    try:
        import ctypes
        if os.name == 'nt' and ctypes.windll.shell32.IsUserAnAdmin() == 0:
            QMessageBox.warning(None, "Admin Rights", 
                              "Packet capture may require administrator privileges on Windows.\n"
                              "Please run as Administrator for best results.")
    except:
        pass
    
    window = OptimizedPacketSnifferGUI()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
