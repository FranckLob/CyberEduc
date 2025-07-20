DROP TABLE IF EXISTS dbuser;

CREATE TABLE dbuser (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(250) NOT NULL,
    password VARCHAR(250) NOT NULL,
    role VARCHAR(250) NOT NULL
);

INSERT INTO dbuser (username, password, role) VALUES 
('dbuser', '$2y$10$qLmj..8TMwtUmRrrDUdgsOMJLsxgFXCQWzHCSSWWyB4I4VaqSrZIO', 'USER'),
('dbadmin', '$2y$10$8p8NohlPNbJUe8I27j6JPOvnL9k6bL71FpsF2/47KoJa3vx7AN0Eq', 'ADMIN');