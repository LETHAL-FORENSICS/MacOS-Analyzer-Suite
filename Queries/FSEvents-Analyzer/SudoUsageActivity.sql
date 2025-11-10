SELECT * FROM FSEventsParser

-- Description: Activity related to a user using the sudo command in the terminal app. The name of the file is the user account issuing the sudo command.
WHERE "Full Path" LIKE '%private/var/db/sudo/%'

-- Sort by event id in ascending order (starting with the earliest date and ending with the most recent one)
ORDER BY CAST("Event ID" as integer) ASC