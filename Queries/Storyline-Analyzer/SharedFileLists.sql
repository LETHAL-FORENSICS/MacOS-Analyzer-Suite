SELECT * FROM Storyline

-- Descriton: Activity related to Shared File List files (.sfl and .sfl2).
WHERE "Path" LIKE '%.sfl' OR "Path" LIKE '%.sfl2'

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC