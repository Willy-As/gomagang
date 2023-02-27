package main

import (
	"errors"
	"gorm.io/gorm"
)

type Intern struct {
	// provided by google
	ID      string `json:"id" gorm:"primaryKey type:varchar(255) not null"`
	Name    string `json:"name" gorm:"type:varchar(255) not null"`
	Email   string `json:"email" gorm:"type:varchar(255) not null unique"`
	Picture string `json:"picture" gorm:"type:varchar(255) not null"`

	// custom attributes
	FullName    *string `json:"full_name" gorm:"type:varchar(255)"`
	School      *string `json:"school" gorm:"type:varchar(255)"`
	PhoneNumber *string `json:"phone_number" gorm:"type:varchar(255)"`
	Division    *string `json:"division" gorm:"type:varchar(255)"`
	Gender      *string `json:"gender" gorm:"type:varchar(255)"`
	StartDate   *string `json:"start_date" gorm:"type:varchar(255)"`
	EndDate     *string `json:"end_date" gorm:"type:varchar(255)"`
}

type Repository struct {
	adminTableName  string
	internTableName string
	db              *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{
		adminTableName:  "admins",
		internTableName: "interns",
		db:              db,
	}
}

var ErrInternAlreadyExists = errors.New("intern already exists")

func (r *Repository) SaveIntern(intern Intern) error {
	var count int64
	err := r.db.Table(r.internTableName).Where("id = ?", intern.ID).Count(&count).Error
	if err != nil {
		return err
	}

	if count > 0 {
		return ErrInternAlreadyExists
	}
	return r.db.Table(r.internTableName).Create(&intern).Error
}

func (r *Repository) UpdateIntern(intern Intern) error {
	return r.db.Table(r.internTableName).Save(&intern).Error
}

func (r *Repository) FindInternByID(id string) (Intern, error) {
	var intern Intern
	err := r.db.Table(r.internTableName).First(&intern, id).Error
	return intern, err
}

func (r *Repository) FindInternByEmail(email string) (Intern, error) {
	var intern Intern
	err := r.db.Table(r.internTableName).Where("email = ?", email).First(&intern).Error
	return intern, err
}

func (r *Repository) FindAllInterns() ([]Intern, error) {
	var interns []Intern
	err := r.db.Table(r.internTableName).Find(&interns).Error
	return interns, err
}
