SELECT * FROM FSEventsParser

-- Description: Activity related to .sh_history file. This has been observed when the commands ‘sudo su’ or ‘sudo -I’ have been successfully executed. When the shell is closed the .sh_history file is modified.
WHERE "Full Path" LIKE '%.sh_history%'

-- Sort by event id in ascending order (starting with the earliest date and ending with the most recent one)
ORDER BY CAST("Event ID" as integer) ASC