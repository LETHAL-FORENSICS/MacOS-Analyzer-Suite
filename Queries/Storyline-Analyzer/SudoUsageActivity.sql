SELECT * FROM Storyline

-- Description: Activity related to a user using the sudo command in the terminal app. The name of the file is the user account issuing the sudo command.
WHERE "Path" LIKE '%private/var/db/sudo/%'

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC