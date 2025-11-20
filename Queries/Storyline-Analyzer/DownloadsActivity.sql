SELECT * FROM Storyline

-- Description: File activity that takes place with the User's Downloads activity.
WHERE "Path" LIKE '%Users/%Downloads/%' AND "Path" NOT LIKE '%com.apple.nsurlsessiond/Download%'

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC