Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$outputBox = New-Object System.Windows.Forms.textbox
$outputBox.Text = "Spinning fish, do he be spinning?"
$outputBox.Multiline = $false
$outputBox.Size = New-Object System.Drawing.Size(100,100)
$outputBox.Location = New-Object System.Drawing.Size(20,80)

$form = New-Object System.Windows.Forms
$form.Text = "Spinning Fish GUI"
$form.Width = 300
$form.Height = 200
$form.BackColor="LightBlue"
$form.Controls.add($outputBox)

$form.Add_Shown({$form.Activate()})
$form.ShowDialog()