SELECT * FROM Storyline

-- Description: File activity related to web browser usage such as Safari or Chrome. This can reveal the full URL that was visited in a web browser or the domain that was being visited.
WHERE ("Path" LIKE '%Users/%/Library%' AND ("Path" LIKE '%www.%' OR "Path" LIKE '%http%')) OR "Path" LIKE '%Users/%/Library/%www.%' OR "Path" LIKE '%Users/%/Library/%http%' OR "Path" LIKE '%Users/%/Library/Caches/Metadata/Safari/History/%' OR "Path" LIKE '%Users/%/Library/Application Support/Google/Chrome/Default/Local Storage/%'

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC