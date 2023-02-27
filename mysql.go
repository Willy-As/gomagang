package main

import (
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"time"
)

func ConnectDB() (*gorm.DB, error) {
	dsn := GetEnv("DSN", "bewarnseuaewn9bv79gy:pscale_pw_TBOGZHZM1pR79ouCQtC2Qgjtsnzv6WXHZb9q3902z3X@tcp(ap-southeast.connect.psdb.cloud)/gomagang?tls=true")
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	err = sqlDB.Ping()
	if err != nil {
		return nil, err
	}

	err = db.AutoMigrate(&Intern{})
	if err != nil {
		return nil, err
	}

	return db, nil
}
