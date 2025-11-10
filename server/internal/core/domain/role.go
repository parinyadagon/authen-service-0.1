package domain

const (
	RoleAdminID     int32 = 1
	RoleDeveloperID int32 = 2
	RoleUserID      int32 = 3
)

type RoleString string

const (
	RoleUser      RoleString = "standard_user"
	RoleAdmin     RoleString = "admin"
	RoleDeveloper RoleString = "developer"
)

type Role struct {
	ID   int32  `json:"id"`
	Name string `json:"name"`
}

type RoleWithPermission struct {
	Role        Role         `json:"role"`
	Permissions []Permission `json:"permissions"`
}
