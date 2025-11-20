SELECT * FROM Storyline

-- Description: Activity related to failed password attempts. The filename includes the user name that was used. These events indicate failed password attempts. This can be the result of running the su or sudo commands in the terminal and entering an incorrect password, being prompted with a dialog window to enter user credentials and entering an incorrect password, or even remote connection attempts with incorrect passwords.
WHERE "Path" LIKE '%rivate/var/db/dslocal/nodes/Default/users/.tmp.%.plist'

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC