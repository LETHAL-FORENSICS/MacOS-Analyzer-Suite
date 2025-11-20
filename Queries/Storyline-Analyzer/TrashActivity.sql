SELECT * FROM Storyline

-- Description: File activity that occurs within the '/Users/<username>/.Trash' folder. For example, when the user sends files to the Trash or empties the Trash.
WHERE "Path" LIKE 'Users/%/.Trash/%'

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC