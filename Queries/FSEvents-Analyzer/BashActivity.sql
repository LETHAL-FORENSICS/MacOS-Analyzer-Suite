SELECT * FROM FSEventsParser

-- Activity related to .bash_sessions history files. 
-- The creating and modification of files with a User's .bash_sessions folder indicates that commands were being run in the Terminal app.
WHERE "Full Path" LIKE 'Users/%/.bash%'

-- Sort by event id in ascending order (starting with the earliest date and ending with the most recent one)
ORDER BY CAST("Event ID" as integer) ASC