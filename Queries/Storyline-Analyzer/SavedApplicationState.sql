SELECT * FROM Storyline

-- Description: Indication that a window was open and the application state was saved.
WHERE "Path" LIKE '%/Saved Application State/%windows.plist'

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC