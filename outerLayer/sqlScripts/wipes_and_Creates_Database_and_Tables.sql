DROP DATABASE IF EXISTS `Hybrid_IDPS`;
CREATE DATABASE IF NOT EXISTS `Hybrid_IDPS`;

USE `Hybrid_IDPS`;

CREATE TABLE outerLayer (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45),
    geolocation VARCHAR(255) NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(50) NULL,
    threat_level TINYINT UNSIGNED NULL,
    source_port INT UNSIGNED NULL,
    destination_port INT UNSIGNED NULL,
    protocol VARCHAR(20) NULL,
    payload TEXT NULL,
    CONSTRAINT chk_outer_threat_level CHECK (threat_level IS NULL OR (threat_level >= 0 AND threat_level <= 10))
);

CREATE TABLE innerLayer (
 id INT AUTO_INCREMENT PRIMARY KEY,
 username VARCHAR(100) NULL,
 target_username VARCHAR(100) NULL,
 ip_address VARCHAR(45),
 geolocation VARCHAR(255) NULL,
 timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 event_type VARCHAR(50) NULL,
 threat_level TINYINT UNSIGNED NULL,
 payload TEXT,
 CONSTRAINT chk_inner_threat_level CHECK (threat_level IS NULL OR (threat_level >= 0 AND threat_level <= 10))
);

CREATE TABLE hybridLayer (
    id INT AUTO_INCREMENT PRIMARY KEY,
    hybrid_column1 VARCHAR(255),
    hybrid_column2 VARCHAR(255)
);
