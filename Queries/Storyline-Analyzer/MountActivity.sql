SELECT * FROM Storyline

-- Description: This will include activity related to mounting and unmounting of DMGs, external devices, network shares, and other mounted volumes.
WHERE ("Path" LIKE 'Volumes/%' OR "Path" like '/Volumes/%') and "Path" NOT LIKE '/Volumes/Preboot/%' and "Path" NOT LIKE '%sparsebundle/%'

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC