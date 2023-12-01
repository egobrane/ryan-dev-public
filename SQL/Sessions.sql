USE egobraneWebDev

SELECT *
FROM TblSession

EXEC Sys_DBVersion

SELECT @@VERSION

RETURN

SELECT *
FROM TblOper
WHERE LoginID = 'egobranedev'

UPDATE dbo.TblOper
SET
	TblOper.LockedOut = 0
WHERE
	TblOper.LoginID = 'egobranedev'

SELECT
	name,
	size/128.0 AS TotalSizeMB,
	CAST(FILEPROPERTY(name, 'SpaceUsed') AS int) / 128.0 AS UsedSpaceMB,
	size/128.0 - CAST(FILEPROPERTY(name, 'SpaceUsed') AS int) / 128.0 AS AvailableSpaceMB,
	physical_name
FROM
	sys.database_files