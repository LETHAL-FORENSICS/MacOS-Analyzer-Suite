SELECT * FROM FSEventsParser

-- FSE_MOUNT = 0x02000000
-- FSE_UNMOUNT = 0x04000000
-- Description: This will include activity related to mounting and unmounting of DMGs, external devices, network shares, and other mounted volumes.
WHERE ("Record Flags" LIKE '%mount%' OR "Full Path" LIKE 'Volumes/%' OR "Full Path" like '/Volumes/%') and "Full Path" NOT LIKE '/Volumes/Preboot/%' and "Full Path" NOT LIKE '%sparsebundle/%'

-- Sort by event id in ascending order (starting with the earliest date and ending with the most recent one)
ORDER BY CAST("Event ID" as integer) ASC