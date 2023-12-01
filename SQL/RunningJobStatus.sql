SELECT session_id, percent_complete, estimated_completion_time, *
FROM sys.dm_exec_requests

-- or use this for more specific time remaining information
SELECT command, percent_complete,
		'elapsed' = total_elapsed_time / 60000.0,
		'remaining' = estimated_completion_time / 60000.0
FROM sys.dm_exec_requests
WHERE command like 'DbccFilesCompact'

-- use this to find what processes are being used and where

EXEC sp_who2