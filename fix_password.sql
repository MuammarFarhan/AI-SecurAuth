-- ============================================================
-- FIX: Update password hash ke format Werkzeug 3.x (scrypt)
-- Jalankan file ini di phpMyAdmin jika sudah import database.sql
-- Password untuk semua user: Admin@123
-- ============================================================

USE `ai_securauth`;

UPDATE `users` SET `password` = 'scrypt:32768:8:1$bTh0Tyg9IOcL6hvX$e9f7985a90176a90cc1a0765d33167a5f28592887d30a0f2285393c1bb33394c47ce224b2b65e718b95baf1ba4692eacd16793855c73f5e4a6d61f6863ed3132'
WHERE `username` = 'admin';

UPDATE `users` SET `password` = 'scrypt:32768:8:1$bzMY2NzMeWFLpQtx$50d4e022d4d998d078d0807c627d0420dfd92198b50d6a173ef45bb42725ed4320a09c4beeab78e39467e0fa99e5d26fb66aec0ca352e8d0ef9b8aa94bada1e8'
WHERE `username` = 'analyst1';

UPDATE `users` SET `password` = 'scrypt:32768:8:1$WFimkijO1zjOYTzM$42dac8eb8c1ae279418a7f7b4f27553cac4885c411dc4710decfcd90cac0708e18e04d7e41c63b5082221f24a540919b08592104eb026e1e594aa592a694dc8d'
WHERE `username` = 'auditor1';

-- Verifikasi hasil update
SELECT username, role, LEFT(password, 30) AS password_preview FROM users;

