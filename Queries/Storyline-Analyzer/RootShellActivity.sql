SELECT * FROM Storyline

-- Description: Activity related to .sh_history file. This has been observed when the commands ‘sudo su’ or ‘sudo -I’ have been successfully executed. When the shell is closed the .sh_history file is modified.
WHERE "Path" LIKE '%.sh_history%'

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC