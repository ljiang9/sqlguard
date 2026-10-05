-- 危险示例：一次塞了好几种风险
SELECT * FROM users WHERE '1'='1' OR 1=1;
DROP TABLE users;
DELETE FROM orders;
