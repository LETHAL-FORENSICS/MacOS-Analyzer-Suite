SELECT * FROM FSEventsParser

-- Description: Activity within the folder '/Users/' that has a file extension of a known image type file.
WHERE "Full Path" LIKE '%Users/%' AND ("Full Path" LIKE '%.tif' OR "Full Path" LIKE '%.tiff' OR "Full Path" LIKE '%.gif' OR "Full Path" LIKE '%.jpeg' OR "Full Path" LIKE '%.jpg' OR "Full Path" LIKE '%.kdc' OR "Full Path" LIKE '%.xbm' OR "Full Path" LIKE '%.jif' OR "Full Path" LIKE '%.jfif' OR "Full Path" LIKE '%.bmp' OR "Full Path" LIKE '%.pcd' OR "Full Path" LIKE '%.png')

-- Sort by event id in ascending order (starting with the earliest date and ending with the most recent one)
ORDER BY CAST("Event ID" as integer) ASC