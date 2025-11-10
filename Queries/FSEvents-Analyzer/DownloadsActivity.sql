SELECT * FROM FSEventsParser

-- Description: File activity that takes place with the User's Downloads activity.
WHERE "Full Path" LIKE '%Users/%Downloads/%' AND "Full Path" NOT LIKE '%com.apple.nsurlsessiond/Download%'

-- Sort by event id in ascending order (starting with the earliest date and ending with the most recent one)
ORDER BY CAST("Event ID" as integer) ASC