SELECT * FROM FSEventsParser

-- Description: File activity related to web browser usage such as Safari or Chrome. This can reveal the full URL that was visited in a web browser or the domain that was being visited.
WHERE ("Full Path" LIKE '%Users/%/Library%' AND ("Full Path" LIKE '%www.%' OR "Full Path" LIKE '%http%')) OR "Full Path" LIKE '%Users/%/Library/%www.%' OR "Full Path" LIKE '%Users/%/Library/%http%' OR "Full Path" LIKE '%Users/%/Library/Caches/Metadata/Safari/History/%' OR "Full Path" LIKE '%Users/%/Library/Application Support/Google/Chrome/Default/Local Storage/%'

-- Sort by event id in ascending order (starting with the earliest date and ending with the most recent one)
ORDER BY CAST("Event ID" as integer) ASC