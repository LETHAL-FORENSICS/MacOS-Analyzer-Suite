SELECT * FROM Storyline

-- Description: All file activity that occurs within the user folders Desktop, Documents, Downloads, Pictures, Videos, and Music.
WHERE "Path" LIKE 'Users/%Desktop/%' OR "Path" LIKE 'Users/%Documents/%' OR "Path" LIKE 'Users/%Downloads/%' OR "Path" LIKE 'Users/%Music/%' OR "Path" LIKE 'Users/%Pictures/%' OR "Path" LIKE 'Users/%Videos/%'

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC