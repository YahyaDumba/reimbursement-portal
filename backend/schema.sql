CREATE TABLE Users(
    UserID INT PRIMARY KEY IDENTITY(1,1),
    Username NVARCHAR(50) NOT NULL UNIQUE,
    PasswordHash NVARCHAR(MAX) NOT NULL,
    Role NVARCHAR(20) CHECK (Role IN ('Employee', 'Manager', 'Admin')) NOT NULL,
    ManagerID INT NULL, -- Self-referencing FK for the hierarchy
    CreatedAt DATETIME DEFAULT GETDATE(),
    FOREIGN KEY (ManagerID) REFERENCES Users(UserID)
)

CREATE TABLE Expenses (
    ExpenseID INT PRIMARY KEY IDENTITY(1,1),
    UserID INT NOT NULL,
    Amount DECIMAL(18, 2) NOT NULL,
    Category NVARCHAR(50) NOT NULL,
    Description NVARCHAR(255),
    ReceiptURL NVARCHAR(MAX),
    Status NVARCHAR(20) DEFAULT 'Pending' CHECK (Status IN ('Pending', 'Approved', 'Rejected')),
    SubmittedAt DATETIME DEFAULT GETDATE(),
    ReviewedAt DATETIME NULL,
    ManagerComment NVARCHAR(255),
    FOREIGN KEY (UserID) REFERENCES Users(UserID)
);

 -- audit log table to track actions on expenses (submission, approval, rejection)
CREATE TABLE AuditLogs (
    LogID BIGINT PRIMARY KEY IDENTITY(1,1),
    ExpenseID INT,
    ActionBy INT, -- UserID of the person who acted
    ActionTaken NVARCHAR(50),
    Timestamp DATETIME DEFAULT GETDATE(),
    FOREIGN KEY (ExpenseID) REFERENCES Expenses(ExpenseID),
    FOREIGN KEY (ActionBy) REFERENCES Users(UserID)
);