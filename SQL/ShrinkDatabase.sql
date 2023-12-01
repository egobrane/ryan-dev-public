SET NOCOUNT ON

DECLARE
	@FileName sysname = N'egobraneWeb_Data',
	@PaddingMB int = 1024,
	@StepSizeMB int = 131072,
	@MaxSteps int = 50;
DECLARE
	@TotalSizeMB int = (SELECT size / 128.0 FROM sys.database_files WHERE name = @FileName),
	@SpaceUsedMB int = (SELECT CAST(FILEPROPERTY(name, 'SpaceUsed') AS int) / 128.0 FROM sys.database_files WHERE name = @FileName),
	@TargetSize int,
	@I int,
	@msg varchar(MAX);
	
SET @TargetSize = @SpaceUsedMB + @PaddingMB;

WHILE @MaxSteps > 0
BEGIN
	SET @TotalSizeMB = (SELECT size / 128.0 FROM sys.database_files WHERE name = @FileName);
	IF @TotalSizeMB <= @TargetSize GOTO done;

	SET @I = @TotalSizeMB - @StepSizeMB;
	IF @I < @TargetSize SET @I = @TargetSize;
	
	DBCC SHRINKFILE(@FileName, @I);
	SET @msg = CONCAT(CURRENT_TIMESTAMP, ': Shrink iteration complete, new size ', @TotalSizeMB, ' MB.');
	RAISERROR(@msg, 0, 0) WITH NOWAIT;
	RAISERROR(' ', 0, 0) WITH NOWAIT;
	--WAITFOR DELAY '00:00:01';  
	SET @MaxSteps = @MaxSteps - 1;
END;


done:
SET @msg = CONCAT(CURRENT_TIMESTAMP, ': Shrink completed, final size ', @TotalSizeMB, ' MB.');
RAISERROR(@msg, 0, 0) WITH NOWAIT;
RAISERROR(' ', 0, 0) WITH NOWAIT;