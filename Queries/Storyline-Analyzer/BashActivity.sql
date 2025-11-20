SELECT * FROM Storyline

-- Activity related to .bash_sessions history files. 
-- The creating and modification of files with a User's .bash_sessions folder indicates that commands were being run in the Terminal app.
WHERE "Path" LIKE 'Users/%/.bash%'

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC