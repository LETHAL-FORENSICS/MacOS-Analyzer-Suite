SELECT * FROM Storyline

-- Events related to usage of the Guest account. When the Guest account is enabled, users can log in to the Guest account and perform activities as a limited user. Once the user logs out the user data is deleted. These events provide insight into what a user was doing while logged in to the Guest account.
WHERE "Path" LIKE '%Users/Guest/%'

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC