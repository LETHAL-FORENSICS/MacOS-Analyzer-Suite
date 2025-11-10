SELECT * FROM FSEventsParser

-- Description: File activity that occurs within the '/Users/<username>/.Trash' folder. For example, when the user sends files to the Trash or empties the Trash.
WHERE "Full Path" LIKE 'Users/%/.Trash/%'

-- Sort by event id in ascending order (starting with the earliest date and ending with the most recent one)
ORDER BY CAST("Event ID" as integer) ASC