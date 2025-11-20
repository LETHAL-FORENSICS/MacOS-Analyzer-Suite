SELECT * FROM Storyline

-- Description: Events related to Microsoft Office documents, PDFs, .Pages, .keynote, and .numbers files.
WHERE "Path" LIKE '%Users/%' AND ("Path" LIKE '%.pages' OR "Path" LIKE '%.numbers' OR "Path" LIKE '%.keynote' OR "Path" LIKE '%.xls' OR "Path" LIKE '%.xlsx' OR "Path" LIKE '%.ppt' OR "Path" LIKE '%.pptx' OR "Path" LIKE '%.doc' OR "Path" LIKE '%.docx' OR "Path" LIKE '%.pdf')

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC