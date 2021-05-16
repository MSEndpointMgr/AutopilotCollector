# Input bindings are passed in via param block.
param($Timer)

$StorageAccountContext = New-AzStorageContext -ConnectionString $env:AzureWebJobsStorage

# Retrieve a specific queue
$AzureQueueStorageName = "autopilot-collector-queue"
$AzureQueueStorage = Get-AzStorageQueue -Name $AzureQueueStorageName -Context $StorageAccountContext

# Create a new message using a constructor of the CloudQueueMessage class
$QueueMessage = [Microsoft.Azure.Storage.Queue.CloudQueueMessage]::new("InvokeFunction")

# Add a new message to the queue
$AzureQueueStorage.CloudQueue.AddMessageAsync($QueueMessage)