SELECT * FROM FSEventsParser

-- Description: Events related to Microsoft Office documents, PDFs, .Pages, .keynote, and .numbers files.
WHERE "Full Path" LIKE '%Users/%' AND ("Full Path" LIKE '%.pages' OR "Full Path" LIKE '%.numbers' OR "Full Path" LIKE '%.keynote' OR "Full Path" LIKE '%.xls' OR "Full Path" LIKE '%.xlsx' OR "Full Path" LIKE '%.ppt' OR "Full Path" LIKE '%.pptx' OR "Full Path" LIKE '%.doc' OR "Full Path" LIKE '%.docx' OR "Full Path" LIKE '%.pdf')

-- Sort by event id in ascending order (starting with the earliest date and ending with the most recent one)
ORDER BY CAST("Event ID" as integer) ASC