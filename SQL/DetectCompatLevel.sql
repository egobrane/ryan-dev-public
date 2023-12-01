SELECT
	databases.compatibility_level
FROM
	sys.databases
WHERE
	databases.name = 'egobraneWeb';