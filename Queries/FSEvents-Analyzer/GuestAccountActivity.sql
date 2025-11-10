SELECT * FROM FSEventsParser

-- Events related to usage of the Guest account. When the Guest account is enabled, users can log in to the Guest account and perform activities as a limited user. Once the user logs out the user data is deleted. These events provide insight into what a user was doing while logged in to the Guest account.
WHERE "Full Path" LIKE '%Users/Guest/%'

-- Sort by event id in ascending order (starting with the earliest date and ending with the most recent one)
ORDER BY CAST("Event ID" as integer) ASC