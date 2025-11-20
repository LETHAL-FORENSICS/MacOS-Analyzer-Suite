SELECT * FROM Storyline

-- Description: Activity within the folder '/Users/' that has a file extension of a known image type file.
WHERE "Path" LIKE '%Users/%' AND ("Path" LIKE '%.tif' OR "Path" LIKE '%.tiff' OR "Path" LIKE '%.gif' OR "Path" LIKE '%.jpeg' OR "Path" LIKE '%.jpg' OR "Path" LIKE '%.kdc' OR "Path" LIKE '%.xbm' OR "Path" LIKE '%.jif' OR "Path" LIKE '%.jfif' OR "Path" LIKE '%.bmp' OR "Path" LIKE '%.pcd' OR "Path" LIKE '%.png')

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC