<#

 -Credential 使用者認證不能用於本機連線 

 -Credential $Credential

 get-help about_Execution_Policies

 Get-ExecutionPolicy
 Restricted
 Set-ExecutionPolicy UnRestricted

#>


$toolver="Ver.0.8c"

$strComputer = "."
$strDomain = "$strComputer\mark"
$Credential=0

Function Check_Admin {
    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
[Security.Principal.WindowsBuiltInRole]  "Administrator"))
    {
        Write-Warning "You do not have Administrator rights to run this script!'nPlease re-run this script as an Administrator!"
        Break
        # 會直接結束程式
    }
    else
    {
        Write-Host "You have Administrator rights!"
    }
}




if($strComputer.Equals(".") -or $strComputer.Equals($env:COMPUTERNAME) )
{

    $Credential=0
    Check_Admin
}
else
{
    $Credential=Get-Credential  $strDomain
}




if($Credential -eq 0 )
{
    $colSettings = Get-WmiObject -namespace root\wmi -class GSA1_ACPIMethod -ComputerName $strComputer 
}
Else
{
    $colSettings = Get-WmiObject -namespace root\wmi -class GSA1_ACPIMethod -ComputerName $strComputer -Credential $Credential
}
#TODO:
#$colSettings | Get-Member
#$colSettings | select InstanceName,Active,__PATH
#$colSettings.GsaGetCapabilityD0().Value.ToString('X8')
$Capability=$colSettings.GsaGetCapabilityD0().Value 
$GsaVersion =[int]$colSettings.GsaGetGSAVersion().Value

Function pause ($message)
{
    # Check if running Powershell ISE
    if ($psISE)
    {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show("$message")
    }
    else
    {
        Write-Host "$message" -ForegroundColor Yellow
        $x = $host.ui.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

if( $GsaVersion -lt 20200609 )
{
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show("BIOS not support IT5702 FWupdate.Please Update BIOS first.Thank You!","Message",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning)
        exit
}

function Convert-ByteArrayToHexString
{
################################################################
#.Synopsis
# Returns a hex representation of a System.Byte[] array as
# one or more strings. Hex format can be changed.
#.Parameter ByteArray
# System.Byte[] array of bytes to put into the file. If you
# pipe this array in, you must pipe the [Ref] to the array.
# Also accepts a single Byte object instead of Byte[].
#.Parameter Width
# Number of hex characters per line of output.
#.Parameter Delimiter
# How each pair of hex characters (each byte of input) will be
# delimited from the next pair in the output. The default
# looks like "0x41,0xFF,0xB9" but you could specify "\x" if
# you want the output like "\x41\xFF\xB9" instead. You do
# not have to worry about an extra comma, semicolon, colon
# or tab appearing before each line of output. The default
# value is ",0x".
#.Parameter Prepend
# An optional string you can prepend to each line of hex
# output, perhaps like '$x += ' to paste into another
# script, hence the single quotes.
#.Parameter AddQuotes
# A switch which will enclose each line in double-quotes.
#.Example
# [Byte[]] $x = 0x41,0x42,0x43,0x44
# Convert-ByteArrayToHexString $x
#
# 0x41,0x42,0x43,0x44
#.Example
# [Byte[]] $x = 0x41,0x42,0x43,0x44
# Convert-ByteArrayToHexString $x -width 2 -delimiter "\x" -addquotes
#
# "\x41\x42"
# "\x43\x44"
################################################################
[CmdletBinding()] Param (
[Parameter(Mandatory = $True, ValueFromPipeline = $True)] [System.Byte[]] $ByteArray,
[Parameter()] [Int] $Width = 10,
[Parameter()] [String] $Delimiter = ",0x",
[Parameter()] [String] $Prepend = "",
[Parameter()] [Switch] $AddQuotes )
 
if ($Width -lt 1) { $Width = 1 }
if ($ByteArray.Length -eq 0) { Return }
$FirstDelimiter = $Delimiter -Replace "^[\,\:\t]",""
$From = 0
$To = $Width - 1
Do
{
$String = [System.BitConverter]::ToString($ByteArray[$From..$To])
$String = $FirstDelimiter + ($String -replace "\-",$Delimiter)
if ($AddQuotes) { $String = '"' + $String + '"' }
if ($Prepend -ne "") { $String = $Prepend + $String }
$String
$From += $Width
$To += $Width
} While ($From -lt $ByteArray.Length)
}
 
Function pause ($message)
{
    # Check if running Powershell ISE
    if ($psISE)
    {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show("$message")
    }
    else
    {
        Write-Host "$message" -ForegroundColor Yellow
        $x = $host.ui.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}
  
function Erase_1k
{
    [CmdletBinding()] Param (
    [Parameter(Mandatory = $True, ValueFromPipeline = $True)] [System.Int32] $addr
    )

    $addrB=[bitconverter]::GetBytes($addr)
 
    $q=new-object byte[] 260 
    $q[0]=0x04
    $q[1]=0x00
    $q[2]=0x00
    $q[3]=0x00
    #0x2000
    $q[4+0]=0xD7
    $q[4+1]=$addrB[2]
    $q[4+2]=$addrB[1]
    $q[4+3]=$addrB[0]
    #$q | format-hex
    #Convert-ByteArrayToHexString $q
     $colSettings.SMBSendByte(2,0xb6,0x17).ret.data
     $colSettings.SMBBlockWrite(2,0xb6,0x18,$q).ret.data 

  #  start-sleep 1
  #'*Switch MCU to I2C programming mode'
     $colSettings.SMBSendByte(2,0xb6,0xFC).ret.data

     $colSettings.SMBSendByte(2,0xb6,0x17).ret.data
     $colSettings.SMBWriteByte(2,0xb6,0x18,0x05).ret.data
     $status=$colSettings.SMBReceiveByte(2,0xb6).ret.data
  #  '[OK]Erase Check PCMD_Read_Status_CMD return {0:x2}' -f $status

 # '*Switch MCU to SMbus programming mode'
     $colSettings.SMBSendByte(2,0xb6,0xFB).ret.data
    write-host ('Erase Address 0x{0:X4} 0x{1:X2}' -f $addr,$status) -foregroundcolor red -backgroundcolor yellow
    start-sleep 0.5
    if($status -ne 0xfc)
    {
       pause "Erase fail!"
    }

} 
function Erase_126k
{  
    $erasesize=126*1024-0x2000
    $eraseblock=$erasesize/0x400
    $erasesize
    $eraseblock
    #$array=0..1
    $array=0..($eraseblock-1)
    foreach ($n in $array)
    {
        'Block : {0}' -f $n
        Erase_1k(0x2000+0x400*$n)
    }
}

function Seti2CEN([Bool]$flag)
{
  if($colSettings.PCIRead16(0,0x0,0x0,0x0).data -eq 0x8086)
  {
  
    if($colSettings.PCIRead16(0,0x1f,0x04,0x0A).data -eq 0x0c05)
    {
       if($flag -eq $true)
       {
               $null=$colSettings.PCIWrite8(0,0x1f,0x04,0x40,$colSettings.PCIRead8(0,0x1f,0x04,0x40).data -bor 0x04)
       }
       else
       {
               $null=$colSettings.PCIWrite8(0,0x1f,0x04,0x40,$colSettings.PCIRead8(0,0x1f,0x04,0x40).data -band 0xfb)
       }

       $null=$colSettings.PCIRead8(0,0x1f,0x04,0x40).data
    }
  }
}
#Seti2cEn($false)




function Read_Flash_Data_Byte
{
    [CmdletBinding()] Param (
    [Parameter(Mandatory = $True, ValueFromPipeline = $True)] [System.Int32] $addr
    )

    $addrB=[bitconverter]::GetBytes($addr)

    $q=new-object byte[] 260 
    $q[0]=0x03
    $q[1]=0x00
    $q[2]=0x00
    $q[3]=0x00
    #0x2000
    $q[4+0]=$addrB[2]
    $q[4+1]=$addrB[1]
    $q[4+2]=$addrB[0]
    #$q | format-hex
    #Convert-ByteArrayToHexString $q
    # '*Switch MCU to SMbus programming mode'
   #  $null=$colSettings.SMBSendByte(2,0xb6,0xFb).ret.data
     $null=$colSettings.SMBBlockWrite(2,0xb6,0x14,$q).ret.data
     $colSettings.SMBReadByte(2,0xb6,0x15).ret.data 
}

function GetBCVer
{
    #$null=Seti2cEn($true)
    #$null=$colSettings.SMBSendByte(2,0xb6,0xFc).ret.data

    $null=Seti2cEn($false)
    $null=$colSettings.SMBSendByte(2,0xb6,0xFb).ret.data


    $local0=$(Read_Flash_Data_Byte 0x3d)
    $local1=$(Read_Flash_Data_Byte 0x3f)
    if( $local0 -in 0x30..0x39)
    {
        if( $local1 -in 0x30..0x39)
        {
            return ($local0 -band 0x0f)*10 + ($local1 -band 0x0f)

        }
    }
    return 0


}
 
function Program_first_cycle_2bytes
{
    [CmdletBinding()] Param (
    [Parameter(Mandatory = $True, ValueFromPipeline = $True)] [System.Int32] $addr,
    [Parameter(Mandatory = $True, ValueFromPipeline = $True)] [System.Byte[]] $data
    )
    #$addr=0x2000
    $length=2
    $addrB=[bitconverter]::GetBytes($addr)
#    'Enable flash write: PCMD_EnableFlashWrite'
#       $colSettings.SMBSendByte(2,0xb6,0x17).ret.data
#       $colSettings.SMBWriteByte(2,0xb6,0x18,0x06).ret.data
#     '[OK]Erase one sector (1024 0x400 bytes)'

    $q=new-object byte[] 260 
    $q[0]=0x04+$length
    $q[1]=0x00
    $q[2]=0x00
    $q[3]=0x00
    #0x2000
    $q[4+0]=0xAD
    $q[4+1]=$addrB[2]
    $q[4+2]=$addrB[1]
    $q[4+3]=$addrB[0]
    foreach ($n in 0..($length-1))
    {
      $q[4+4+$n]=$data[$n]
    }
    #Convert-ByteArrayToHexString $q
    #$q | format-hex
    $colSettings.SMBSendByte(2,0xb6,0x17).ret.data
    $colSettings.SMBBlockWrite(2,0xb6,0x18,$q).ret.data 

   # start-sleep 1
  #'*Switch MCU to I2C programming mode'
   $colSettings.SMBSendByte(2,0xb6,0xFC).ret.data

     $colSettings.SMBSendByte(2,0xb6,0x17).ret.data
     $colSettings.SMBWriteByte(2,0xb6,0x18,0x05).ret.data
     $status=$colSettings.SMBReceiveByte(2,0xb6).ret.data
    #'[OK]Program Check PCMD_Read_Status_CMD return {0:x2}' -f $status
 
  #'*Switch MCU to SMbus programming mode'
   $colSettings.SMBSendByte(2,0xb6,0xFB).ret.data

    write-host ('Program Address 0x{0:X4} 0x{1:X2}' -f $addr,$status) -foregroundcolor red -backgroundcolor yellow
    if($status -ne 0xfe)
    {
       pause "Program_first_cycle_2bytes"
    }

} 

function Program_other_cycle_30bytes
{
    [CmdletBinding()] Param (
    [Parameter(Mandatory = $True, ValueFromPipeline = $True)] [System.Byte[]] $data
    )
    $length=30
    $q=new-object byte[] 260 
    $q[0]=$length
    $q[1]=0x00
    $q[2]=0x00
    $q[3]=0x00
    foreach ($n in 0..($length-1))
    {
      $q[4+$n]=$data[$n]
    }
    #Convert-ByteArrayToHexString $q
    #$q | format-hex
    $status=$colSettings.SMBBlockWrite(2,0xb6,0xAD,$q).ret.data 
    if($status -ne 1)
    {
      pause "Program_other_cycle_30bytes"
    }

}   
function Program_other_cycle_32bytes
{
    [CmdletBinding()] Param (
    [Parameter(Mandatory = $True, ValueFromPipeline = $True)] [System.Byte[]] $data
    )
    $length=32
    $q=new-object byte[] 260 
    $q[0]=$length
    $q[1]=0x00
    $q[2]=0x00
    $q[3]=0x00
    foreach ($n in 0..($length-1))
    {
      $q[4+$n]=$data[$n]
    }
    #$q[4+4]=$addrB[2]
    #$q[4+5]=$addrB[2]
    #Convert-ByteArrayToHexString $q

    $status=$colSettings.SMBBlockWrite(2,0xb6,0xAD,$q).ret.data 
    if($status -ne 1)
    {
      pause "Program_other_cycle_32bytes"
    }

}   

   
function Program_126k
{
    [CmdletBinding()] Param (
    #[Parameter(Mandatory = $True, ValueFromPipeline = $True)] [System.Int32] $addr
    )
    'Enable flash write: PCMD_EnableFlashWrite'
    $colSettings.SMBSendByte(2,0xb6,0x17).ret.data
    $colSettings.SMBWriteByte(2,0xb6,0x18,0x06).ret.data


   [Byte[]] $aa=0x30..0x80
    Program_first_cycle_2bytes  0x2000 $aa 
    Program_other_cycle_30bytes $aa
    foreach( $n in 1..32)
    {
        Program_other_cycle_32bytes $aa
    }
  

    'Disable flash write:PCMD_DisableFlashWrite'
    $colSettings.SMBSendByte(2,0xb6,0x17).ret.data
    $colSettings.SMBWriteByte(2,0xb6,0x18,0x04).ret.data



} 
function Enable_flash_write
{
   '---------------------------------------------Enable flash write'
  # '*Switch MCU to I2C programming mode'
   $colSettings.SMBSendByte(2,0xb6,0xFC).ret.data
   # 'Enable flash write: PCMD_EnableFlashWrite'
       $colSettings.SMBSendByte(2,0xb6,0x17).ret.data
       $colSettings.SMBWriteByte(2,0xb6,0x18,0x06).ret.data


  # '*Switch MCU to SMbus programming mode'
   $colSettings.SMBSendByte(2,0xb6,0xFB).ret.data
}

function Disable_flash_write
{
  '---------------------------------------------Disable flash write'
  #'Switch MCU to I2C programming mode'
   $colSettings.SMBSendByte(2,0xb6,0xFC).ret.data

   # 'Disable flash write:PCMD_DisableFlashWrite'
    $colSettings.SMBSendByte(2,0xb6,0x17).ret.data
    $colSettings.SMBWriteByte(2,0xb6,0x18,0x04).ret.data

  #'*Switch MCU to SMbus programming mode'
   $colSettings.SMBSendByte(2,0xb6,0xFB).ret.data
}

#GUID=56E14F88-234B-4C34-B204-299670447247 $BDR
function SearchBDRHeader()
{
 #0x41825F0A 
  $fvaddr = [UINT32](0x7ffffffc)
  $fvaddr = $fvaddr -bor 0x80000000
  $fvaddr=$colSettings.MemRead32Bits([UINT32]$fvaddr,0,32).data
  #'{0:x4}' -f $fvaddr
  $fvlen=[UINT32] 0x7fffffff 
  $fvlen = $fvlen -bor 0x80000000
  #'{0:x4}' -f $fvlen
   $fvlen= $fvlen -  $fvaddr + 1
 
   #'{0:x4}' -f $fvlen

        $data=$colSettings.MemRead32Bits([UINT32]$fvaddr+0x28,0,32).data
        if( $data -eq 0x4856465F)
        {
          $i=0
          $num=$fvlen-$colSettings.MemRead32Bits([UINT32]$fvaddr+0x30,0,16).data
          $ffsaddr=[UINT32]($fvaddr+0x48)

          while($num -ne 0)
          {
            $guid=$colSettings.MemRead32Bits($ffsaddr,0,32).data
            $ffslen=($colSettings.MemRead32Bits($ffsaddr+0x14,0,24).data + 7) -band 0xfffffff8
            #'{0} {1:X4}  {2:X4} {3:X4}-* {4:X4}' -f $i,$num,$ffsaddr,$guid,$ffslen

            #GUID=56E14F88-234B-4C34-B204-299670447247 $BDR
            $data1=$colSettings.MemRead32Bits($ffsaddr,0,32).data
            $data2=$colSettings.MemRead32Bits($ffsaddr+0x1c,0,32).data
            if(($data1 -eq 0x56E14F88) -and ($data2 -eq 0x52444224))
            {
               return $ffsaddr+0x1c
            }
            $ffsaddr=$ffsaddr+$ffslen
            $num = $num - $ffslen
            $i+=1
          }
        }
        return 0
}
#GUID=41825F0A-7447-4159-B435-97987E47043F #$FWC
function SearchFwcHeader()
{
 #0x41825F0A 
  $fvaddr = [UINT32](0x7ffffffc)
  $fvaddr = $fvaddr -bor 0x80000000
  $fvaddr=$colSettings.MemRead32Bits([UINT32]$fvaddr,0,32).data
  #'{0:x4}' -f $fvaddr
  $fvlen=[UINT32] 0x7fffffff 
  $fvlen = $fvlen -bor 0x80000000
  #'{0:x4}' -f $fvlen
   $fvlen= $fvlen -  $fvaddr + 1
 
   #'{0:x4}' -f $fvlen

        $data=$colSettings.MemRead32Bits([UINT32]$fvaddr+0x28,0,32).data
        if( $data -eq 0x4856465F)
        {
          $i=0
          $num=$fvlen-$colSettings.MemRead32Bits([UINT32]$fvaddr+0x30,0,16).data
          $ffsaddr=[UINT32]($fvaddr+0x48)

          while($num -ne 0)
          {
            $guid=$colSettings.MemRead32Bits($ffsaddr,0,32).data
            $ffslen=($colSettings.MemRead32Bits($ffsaddr+0x14,0,24).data + 7) -band 0xfffffff8
            #'{0} {1:X4}  {2:X4} {3:X4}-* {4:X4}' -f $i,$num,$ffsaddr,$guid,$ffslen

            #GUID=41825F0A-7447-4159-B435-97987E47043F
            #$FWC
            $data1=$colSettings.MemRead32Bits($ffsaddr,0,32).data
            $data2=$colSettings.MemRead32Bits($ffsaddr+0x1c,0,32).data
            if(($data1 -eq 0x41825F0A) -and ($data2 -eq 0x43574624))
            {
               return $ffsaddr+0x1c
            }
            $ffsaddr=$ffsaddr+$ffslen
            $num = $num - $ffslen
            $i+=1
          }
        }
        return 0
}


<#
//Predefine Command
#define Read_ID_CMD		0x9F
#define Sector_Erase_CMD	0xD7
#define Fast_Read_CMD		0x0B
#define Write_Enable_CMD	0x06
#define Write_Disable_CMD	0x04
#define Read_Status_CMD	0x05
#define Fast_AAIW_CMD		0xAD
#define I2EC_Address_CMD	0x10
#define I2EC_Data_CMD		0x11
#define PCMD_SPI_CMD		0x18
#define Switch_to_I2C		0xFC
#define Switch_Back_SMBUS	0xFB

#>

Function pause ($message)
{
    # Check if running Powershell ISE
    if ($psISE)
    {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show("$message")
    }
    else
    {
        Write-Host "$message" -ForegroundColor Yellow
        $x = $host.ui.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

Function SwitchNormalToFlashMode
{

  if($colSettings.SMBWriteByte(2,0xd0,0xef,0).ret.data -eq 1)
  {
      'Switch 0xB6 to Flash_Mode.......'

  }


   'Switch MCU to SMbus programming mode'
   $colSettings.SMBSendByte(2,0xb6,0xFB).ret.data


   '---------------------------------------------Flash ID'
'[OK]Get Flash ID: Length:2 0xFFFE' 
 
 $local1=$colSettings.SMBReadWord(2,0xb6,0xEE).ret.data 
 
 '{0:X4}' -f $colSettings.SMBReadWord(2,0xb6,0xEE).ret.data
 '*Switch MCU to I2C programming mode'
 $colSettings.SMBSendByte(2,0xb6,0xFC).ret.data

   $colSettings.SMBSendByte(2,0xb6,0x17).ret.data
   $colSettings.SMBWriteByte(2,0xb6,0x18,0x9f).ret.data
   $local0=$colSettings.SMBReceiveByte(2,0xb6).ret.data
   $local1=$colSettings.SMBReceiveByte(2,0xb6).ret.data

 '*Switch MCU to SMbus programming mode'
 $colSettings.SMBSendByte(2,0xb6,0xFB).ret.data


   $local0= ($local1) + (($local0 ) -shl 8)
 write-host  ('GetFlashID=0x{0:X4} from 0xB6....' -f $local0)  -foregroundcolor red -backgroundcolor yellow

   '---------------------------------------------Chip ID'
'[OK]Get Chip ID: Length:2 0x5702'
   $colSettings.SMBSendByte(2,0xb6,0x17).ret.data
   'I2EC_Address_CMD'
   $colSettings.SMBWriteWord(2,0xb6,0x10,0x0020).ret.data
   'I2EC_Data_CMD'
     $local0=$colSettings.SMBReadWord(2,0xb6,0x11).ret.data
    $local0= ($local0 -shr 8) + (($local0 -band 0xff) -shl 8)
   write-host  ('GetChipID=0x{0:X4} from 0xB6....\n' -f  $local0)  -foregroundcolor red -backgroundcolor yellow


}
Function SwitchFlashToNormalMode
{
  if($colSettings.SMBWriteByte(2,0xb6,0x5A,0xA5).ret.data -eq 1)
  {
      'Switch 0xB6 to Normal_Mode.......'
      start-sleep 0.5

  }
  
'Enter Normal WriteMode'
    $colSettings.SMBWriteByte(2,0xD0,0xE1,0x01).ret.data
  '---------------------------------------------CheckSum'
'[OK]Get CheckSum: Length:2 0xDC6E' 

'Enter Normal WriteMode'
    $colSettings.SMBWriteByte(2,0xD0,0xE1,0x01).ret.data


  $local0= $colSettings.SMBReadWord(2,0xD0,0xEE).ret.data
  $local0= ($local0 -shr 8) + (($local0 -band 0xff) -shl 8)
 write-host  ('GetCheckSum=0x{0:X4} from 0xD0....' -f $local0)  -foregroundcolor red -backgroundcolor yellow


'Enter Fast WriteMode'
    $colSettings.SMBWriteByte(2,0xD0,0xE1,0x00).ret.data
'---------------------------------------------0x3CA5C35A' 
'0x3CA5C35A read : offset:0x10 Length:4'
    $ww=$colSettings.SMBBlockRead(2,0xD0,0x10).ret
    $aa=$ww.bytes| select -first $ww.length 
    Convert-ByteArrayToHexString $aa
 'Smbus Bus[{0}]:Addr[0x{1:X2}]:Cmd[0x{2:X2}]=0x{3:X4} BIOS Size ' -f 2,0xD0,0x19,$colSettings.SMBReadWord(2,0xd0,0x19).ret.data     
 '---------------------------------------------BIOS Name'    
 'BIOS Name read "GIGABYTE": offset:0x18 Length:8'
    $ww=$colSettings.SMBBlockRead(2,0xd0,0x18).ret
    $aa=$ww.bytes| select -first $ww.length 
    Convert-ByteArrayToHexString $aa 
  '---------------------------------------------FW Version'     
'FW Version: offset:0xEC Length:4'
    $ww=$colSettings.SMBBlockRead(2,0xD0,0xEC).ret
    $aa=$ww.bytes| select -first $ww.length 
    Convert-ByteArrayToHexString $aa
  '---------------------------------------------GetChipID'     
     
    $local0=$colSettings.SMBReadWord(2,0xD0,0xED).ret.data
    $local0= ($local0 -shr 8) + (($local0 -band 0xff) -shl 8)
    'GetChipID=0x{0:X4} from 0xD0....' -f  $local0

}


Function CheckFwc([uint32] $id)
{
    $FWCAddr=$(SearchFWCHeader)
    if( $FWCAddr -eq 0)
    {
        #pause "FWC signature not found!"
    }
    else
    {
        $data=$colSettings.MemRead32Bits([UINT32]$FWCAddr+0x8,0,32).data
        #'{0:X4} {1:X4}' -f  $data,$FWCAddr
        if( $data -ne 0x54424724) #$GBT
        {
           #pause "GBT signature not found!"
        }
        else
        {
           $fwc_number=$colSettings.MemRead32Bits([UINT32]$FWCAddr+0x6,0,8).data
           for($i=0;$i -lt $fwc_number; $i++)
           { 
                $fwc_1=$colSettings.MemRead32Bits([UINT32]$FWCAddr+0x10+$i*4,0,32).data
                if($fwc_1 -eq $id)
                {
                    return $true
                }
           }
        }
    }
    return $false
}


<#
#*****************************************************************************************For 1st and  2nd IT5702
# 0x01000201: Z490 AORUS XTREME WF 2nd IT5702
# 0x03000201: Z490 AORUS XTREME 2nd IT5702
# 0x04000201: Z490 AORUS MASTER
# 	      Z490 AORUS XTREME WF 1st IT5702
#	      Z490 AORUS XTREME 1st IT5702
#             Z490 AORUS ULTRA
#             Z490 AORUS PRO
#             Z490 AORUS ELITE
#             Z490I AORUS ULTRA
#             Z490 DESIGNARE
#             Z490 WHITE
#             Z490 GAMING X
#             Z490M GAMING X
#             Z490 UD
#             Z490 M
#             H470 AORUS PRO AX
#             H470 HD3
#             H470M DS3H
#             H470N AX
#             B460 AORUS PRO AC
#             B460M AORUS PRO
#             B460M DS3H
#*****************************************************************************************

#*****************************************************************************************For IT8795 EC
# 0x24000101: Z490 AORUS XTREME WF
# 0x25000101: Z490 AORUS XTREME
# 0x26000101: Z490 AORUS MASTER
# 0x27000101: Z490 AORUS PRO
#             Z490 AORUS ULTRA
#             Z490 DESIGNARE
#*****************************************************************************************
#>



Function IT5702_ProgramD0( [BYTE[]] $array)
{




<#

   Enable_flash_write
    for ($i = 8*1024 ; $i -lt 126*1024; $i+=1024)
    {
       Erase_1k($i)
    }
    Disable_flash_write
    
 

    
    
    $data = $array | select -skip 0x2000 -first 2
    Program_first_cycle_2bytes 0x2000  $data
    $data = $array | select -skip (0x2000+2) -first 30
    Program_other_cycle_30bytes  $data
    
    for ($i =  (0x2000+32) ; $i -lt 126*1024; $i+=32)
    {
       if(($i % 1024) -eq 0)
       {
         write-host  ('{0} @ 0x{1:X4}' -f ($i/(128*1024)).tostring("P"),$i)  -foregroundcolor yellow -backgroundcolor red
       }
         $data = $array | select -skip $i -first 32
         Program_other_cycle_32bytes  $data
         
     }

#>

<#

   for ($i = 8*1024 ; $i -lt 126*1024; $i+=1024)
    {
        Enable_flash_write
        Erase_1k($i)
        Disable_flash_write
 
 
    }   

 Enable_flash_write 
 [Byte[]] $data=@(0..255)*4*126
 Program_first_cycle_2bytes 0x2000  $data
 #start-sleep 0.2 
 $data=($data | select -skip 2 )
 Program_other_cycle_30bytes  $data
 $data=($data | select -skip 30 )
 #start-sleep 0.2 
# pause
    for ($i = 8*1024+32 ; $i -lt 126*1024; $i+=32)
    {
            #'{0:x4}' -f $i
            Program_other_cycle_32bytes  ($data | select -first 32)
            $data=($data | select -skip 32 )
            if ( ($i % 1024) -eq 32 )
            {
              write-host  ('{0} {1:x4}' -f ($i/(128*1024)).tostring("P"),$i)  -foregroundcolor yellow -backgroundcolor red
            }
            #start-sleep 0.2
           # pause
    }
 Disable_flash_write    
    
#>      
         
    for ($i = 8*1024 ; $i -lt 126*1024; $i+=1024)
    {
        #'Address : {0:X4} {1:X2}' -f $i,[BYTE]($i/1024)
        $data = $array | select -skip $i -first 1024

        write-host  ('{0} 0x{1:X4}' -f (($i+$j)/(128*1024)).tostring("P"),$i)  -foregroundcolor yellow -backgroundcolor red
        $labels.Text= ('Process {0} 0x{1:X4}' -f (($i+$j)/(128*1024)).tostring("P"),$i)
        if($global:mbbcfwver -lt 4)
        {
            Seti2cEn($true)

        }
        else
        {
            Seti2cEn($false)
        }        #'---------------------------------------------Erase 1K'
        $null=Enable_flash_write
        $null=Erase_1k($i)
        $null=Disable_flash_write

        #'---------------------------------------------Program 1K'
        $null=Enable_flash_write 


        #[Byte[]] $data=@(@([Byte]($i/1024))*256)*4
        #[Byte[]] $data=@(0..255)*4
         $null=Program_first_cycle_2bytes $i  $data 
       # start-sleep 0.2
        $data=($data | select -skip 2 )
         $null=Program_other_cycle_30bytes  $data
       # start-sleep 0.2
        $data=($data | select -skip 30 )
        for ($j = 32 ; $j -lt 1024; $j+=32)
        {
            $null= Program_other_cycle_32bytes  $data
            $data=($data | select -skip 32 )
         #   write-host  ('{0}' -f (($i+$j)/(128*1024)).tostring("P"))  -foregroundcolor yellow -backgroundcolor red
     #       start-sleep 0.5
        }
        $null=Disable_flash_write
        Seti2cEn($false)

        
    }
    write-host  "Complete!" -foregroundcolor yellow -backgroundcolor red
  

<#
    for ($i = 8*1024 ; $i -lt 126*1024; $i+=1024)
    {
       # 'Address : {0:X4} {1:X2}' -f $i,[BYTE]($i/1024)
        $data = $array | select -skip $i -first 1024
       # '---------------------------------------------Program 1K'
        #[Byte[]] $data=@(@([Byte]($i/1024))*256)*4
        [Byte[]] $data=@(0..255)*4

        for ($j = 0 ; $j -lt 1024; $j+=16)
        {
        Enable_flash_write 
            Program_first_cycle_2bytes ($i+$j)  $data 
            #start-sleep 0.2
            $data=($data | select -skip 2 )
            Program_other_cycle_14bytes  $data
            #start-sleep 0.2
            $data=($data | select -skip 14 )
           
            #bug : Program_other_cycle_32bytes  $data
            ##start-sleep 0.2
            #$data=($data | select -skip 32 )



            if ( (($i+$j) % 1024) -eq 0 )
            {
              write-host  ('{0} {1:x4}' -f (($i+$j)/(128*1024)).tostring("P"),($i+$j))  -foregroundcolor yellow -backgroundcolor red
            }

        Disable_flash_write
        }
    }
#>
<#
for ($i = 8*1024 ; $i -lt 9*1024; $i+=1024)
    {
        Enable_flash_write
        Erase_1k($i)
        Disable_flash_write
 
 
    }   



    for ($i = 8*1024 ; $i -lt 9*1024; $i+=1024)
    {
       # 'Address : {0:X4} {1:X2}' -f $i,[BYTE]($i/1024)
        $data = $array | select -skip $i -first 1024
       # '---------------------------------------------Program 1K'
        #[Byte[]] $data=@(@([Byte]($i/1024))*256)*4
        [Byte[]] $data=@(0..255)*4

        for ($j = 0 ; $j -lt 1024; $j+=32)
        {
        $null=Enable_flash_write 
            $null=Program_first_cycle_2bytes ($i+$j)  $data 
            #start-sleep 0.2
            $data=($data | select -skip 2 )
            $null=Program_other_cycle_30bytes  $data
            #start-sleep 0.2
            $data=($data | select -skip 30 )

            if ( (($i+$j) % 1024) -eq 0 )
            {
              write-host  ('{0} {1:x4}' -f (($i+$j)/(128*1024)).tostring("P"),($i+$j))  -foregroundcolor yellow -backgroundcolor red
            }
            start-sleep 0.2

        $null=Disable_flash_write
        }
    }
#>
<# fail case
    for ($i = 8*1024 ; $i -lt 126*1024; $i+=1024)
    {
       # 'Address : {0:X4} {1:X2}' -f $i,[BYTE]($i/1024)
        $data = $array | select -skip $i -first 1024
       # '---------------------------------------------Program 1K'
        #[Byte[]] $data=@(@([Byte]($i/1024))*256)*4
        [Byte[]] $data=@(0..255)*4

        for ($j = 0 ; $j -lt 1024; $j+=32)
        {
        $null=Enable_flash_write 
            $null=Program_first_cycle_32bytes ($i+$j)  $data 
            $data=($data | select -skip 32 )
           
            #bug : Program_other_cycle_32bytes  $data
            ##start-sleep 0.2
            #$data=($data | select -skip 32 )

            if ( (($i+$j) % 1024) -eq 0 )
            {
              write-host  ('{0} {1:x4}' -f (($i+$j)/(128*1024)).tostring("P"),($i+$j))  -foregroundcolor yellow -backgroundcolor red
            }
           # start-sleep 0.2

        $null=Disable_flash_write
        }
    }
#>
}
Function IT5702_ProgramC8( [BYTE[]] $array)
{
<#

   Enable_flash_write
    for ($i = 8*1024 ; $i -lt 126*1024; $i+=1024)
    {
       Erase_1k($i)
    }
    Disable_flash_write
    
 

    
    
    $data = $array | select -skip 0x2000 -first 2
    Program_first_cycle_2bytes 0x2000  $data
    $data = $array | select -skip (0x2000+2) -first 30
    Program_other_cycle_30bytes  $data
    
    for ($i =  (0x2000+32) ; $i -lt 126*1024; $i+=32)
    {
       if(($i % 1024) -eq 0)
       {
         write-host  ('{0} @ 0x{1:X4}' -f ($i/(128*1024)).tostring("P"),$i)  -foregroundcolor yellow -backgroundcolor red
       }
         $data = $array | select -skip $i -first 32
         Program_other_cycle_32bytes  $data
         
     }

#>

<#

   for ($i = 8*1024 ; $i -lt 126*1024; $i+=1024)
    {
        Enable_flash_write
        Erase_1k($i)
        Disable_flash_write
 
 
    }   

 Enable_flash_write 
 [Byte[]] $data=@(0..255)*4*126
 Program_first_cycle_2bytes 0x2000  $data
 #start-sleep 0.2 
 $data=($data | select -skip 2 )
 Program_other_cycle_30bytes  $data
 $data=($data | select -skip 30 )
 #start-sleep 0.2 
# pause
    for ($i = 8*1024+32 ; $i -lt 126*1024; $i+=32)
    {
            #'{0:x4}' -f $i
            Program_other_cycle_32bytes  ($data | select -first 32)
            $data=($data | select -skip 32 )
            if ( ($i % 1024) -eq 32 )
            {
              write-host  ('{0} {1:x4}' -f ($i/(128*1024)).tostring("P"),$i)  -foregroundcolor yellow -backgroundcolor red
            }
            #start-sleep 0.2
           # pause
    }
 Disable_flash_write    
    
#>      
         
    for ($i = 8*1024 ; $i -lt 126*1024; $i+=1024)
    {
        #'Address : {0:X4} {1:X2}' -f $i,[BYTE]($i/1024)
        $data = $array | select -skip $i -first 1024

        write-host  ('{0} 0x{1:X4}' -f (($i+$j)/(128*1024)).tostring("P"),$i)  -foregroundcolor yellow -backgroundcolor red
        $labels2.Text= ('Process {0} 0x{1:X4}' -f (($i+$j)/(128*1024)).tostring("P"),$i)
        #'---------------------------------------------Erase 1K'
        if($global:mbbcfwvermcu -lt 4)
        {
            Seti2cEn($true)

        }
        else
        {
            Seti2cEn($false)
        }
       # Seti2cEn($false)
        $null=Enable_flash_write
        $null=Erase_1k($i)
        $null=Disable_flash_write
        
        #'---------------------------------------------Program 1K'

        $null=Enable_flash_write 


        #[Byte[]] $data=@(@([Byte]($i/1024))*256)*4
        #[Byte[]] $data=@(0..255)*4
         $null=Program_first_cycle_2bytes $i  $data 
       # start-sleep 0.2
        $data=($data | select -skip 2 )
         $null=Program_other_cycle_30bytes  $data
       # start-sleep 0.2
        $data=($data | select -skip 30 )
        for ($j = 32 ; $j -lt 1024; $j+=32)
        {
            $null= Program_other_cycle_32bytes  $data
            $data=($data | select -skip 32 )
         #   write-host  ('{0}' -f (($i+$j)/(128*1024)).tostring("P"))  -foregroundcolor yellow -backgroundcolor red
     #       start-sleep 0.5
        }

        $null=Disable_flash_write

        Seti2cEn($false)
        
    }
    write-host  "Complete!" -foregroundcolor yellow -backgroundcolor red
  

<#
    for ($i = 8*1024 ; $i -lt 126*1024; $i+=1024)
    {
       # 'Address : {0:X4} {1:X2}' -f $i,[BYTE]($i/1024)
        $data = $array | select -skip $i -first 1024
       # '---------------------------------------------Program 1K'
        #[Byte[]] $data=@(@([Byte]($i/1024))*256)*4
        [Byte[]] $data=@(0..255)*4

        for ($j = 0 ; $j -lt 1024; $j+=16)
        {
        Enable_flash_write 
            Program_first_cycle_2bytes ($i+$j)  $data 
            #start-sleep 0.2
            $data=($data | select -skip 2 )
            Program_other_cycle_14bytes  $data
            #start-sleep 0.2
            $data=($data | select -skip 14 )
           
            #bug : Program_other_cycle_32bytes  $data
            ##start-sleep 0.2
            #$data=($data | select -skip 32 )



            if ( (($i+$j) % 1024) -eq 0 )
            {
              write-host  ('{0} {1:x4}' -f (($i+$j)/(128*1024)).tostring("P"),($i+$j))  -foregroundcolor yellow -backgroundcolor red
            }

        Disable_flash_write
        }
    }
#>
<#
for ($i = 8*1024 ; $i -lt 9*1024; $i+=1024)
    {
        Enable_flash_write
        Erase_1k($i)
        Disable_flash_write
 
 
    }   



    for ($i = 8*1024 ; $i -lt 9*1024; $i+=1024)
    {
       # 'Address : {0:X4} {1:X2}' -f $i,[BYTE]($i/1024)
        $data = $array | select -skip $i -first 1024
       # '---------------------------------------------Program 1K'
        #[Byte[]] $data=@(@([Byte]($i/1024))*256)*4
        [Byte[]] $data=@(0..255)*4

        for ($j = 0 ; $j -lt 1024; $j+=32)
        {
        $null=Enable_flash_write 
            $null=Program_first_cycle_2bytes ($i+$j)  $data 
            #start-sleep 0.2
            $data=($data | select -skip 2 )
            $null=Program_other_cycle_30bytes  $data
            #start-sleep 0.2
            $data=($data | select -skip 30 )

            if ( (($i+$j) % 1024) -eq 0 )
            {
              write-host  ('{0} {1:x4}' -f (($i+$j)/(128*1024)).tostring("P"),($i+$j))  -foregroundcolor yellow -backgroundcolor red
            }
            start-sleep 0.2

        $null=Disable_flash_write
        }
    }
#>
<# fail case
    for ($i = 8*1024 ; $i -lt 126*1024; $i+=1024)
    {
       # 'Address : {0:X4} {1:X2}' -f $i,[BYTE]($i/1024)
        $data = $array | select -skip $i -first 1024
       # '---------------------------------------------Program 1K'
        #[Byte[]] $data=@(@([Byte]($i/1024))*256)*4
        [Byte[]] $data=@(0..255)*4

        for ($j = 0 ; $j -lt 1024; $j+=32)
        {
        $null=Enable_flash_write 
            $null=Program_first_cycle_32bytes ($i+$j)  $data 
            $data=($data | select -skip 32 )
           
            #bug : Program_other_cycle_32bytes  $data
            ##start-sleep 0.2
            #$data=($data | select -skip 32 )

            if ( (($i+$j) % 1024) -eq 0 )
            {
              write-host  ('{0} {1:x4}' -f (($i+$j)/(128*1024)).tostring("P"),($i+$j))  -foregroundcolor yellow -backgroundcolor red
            }
           # start-sleep 0.2

        $null=Disable_flash_write
        }
    }
#>
}

Function GetFWImageInfoD0($bytes)
{
    #$bytes | select -skip 0x2014 -first 0x1c
     $global:filechecksum=[BitConverter]::touint16(($bytes | select -skip 0x2000 -first 2),0)
    'Checksum=0x{0:X2}' -f $global:filechecksum
     
     $ver= [System.Text.Encoding]::ASCII.GetString(($bytes | select -skip 0x2014 -first ($bytes | select -skip 0x2014 -first 40).IndexOf(0x00)))
     $temp=$ver.split(" ")
     $global:filechipid=$temp[0]
     'Chipid={0}'  -f $global:filechipid

     $global:filefwver=($ver.split("V"))[1]
     'Ver={0}'  -f  $global:filefwver
     #[System.Text.Encoding]::ASCII.GetString(($bytes | select -skip 0x2030 -first 0x4))
     #Convert-ByteArrayToHexString  (($bytes | select -skip 0x2034 -first 4)[-1..-4]) -delimiter ""
     $global:filefwcode=[BitConverter]::touint32(($bytes | select -skip 0x2034 -first 4),0)
     'FWC=0x{0:x4}'  -f $global:filefwcode


}

Function GetFileDataD0([String]$file)
{

    $bytes =[BYTE[]] [System.IO.File]::ReadAllBytes($file)
    $aa=[BitConverter]::touint32(($bytes | select -skip 0x2030 -first 4),0) 
    if($aa -eq 0x43574624) # $FWC signature
    {
        (GetFWImageInfoD0 $bytes) -join "`n"
        'Size={0}K Bytes' -f ((Get-Item $file).length/1024)
   #'Date={0}' -f ((Get-Item $file).CreationTime)
    }

}
Function GetFWImageInfoC8($bytes)
{
    #$bytes | select -skip 0x2014 -first 0x1c
     $global:filechecksummcu=[BitConverter]::touint16(($bytes | select -skip 0x2000 -first 2),0)
    'Checksum=0x{0:X2}' -f $global:filechecksummcu
     
     $ver= [System.Text.Encoding]::ASCII.GetString(($bytes | select -skip 0x2014 -first ($bytes | select -skip 0x2014 -first 40).IndexOf(0x00)))
     $temp=$ver.split(" ")
     $global:filechipidmcu=$temp[0]
     'Chipid={0}'  -f $global:filechipidmcu

     $global:filefwvermcu=($ver.split("V"))[1]
     'Ver={0}'  -f  $global:filefwvermcu
     #[System.Text.Encoding]::ASCII.GetString(($bytes | select -skip 0x2030 -first 0x4))
     #Convert-ByteArrayToHexString  (($bytes | select -skip 0x2034 -first 4)[-1..-4]) -delimiter ""
     $global:filefwcodemcu=[BitConverter]::touint32(($bytes | select -skip 0x2034 -first 4),0)
     'FWC=0x{0:x4}'  -f $global:filefwcodemcu


}

Function GetFileDataC8([String]$file)
{

    $bytes =[BYTE[]] [System.IO.File]::ReadAllBytes($file)
    $aa=[BitConverter]::touint32(($bytes | select -skip 0x2030 -first 4),0) 
    if($aa -eq 0x43574624) # $FWC signature
    {
        (GetFWImageInfoC8 $bytes) -join "`n"
        'Size={0}K Bytes' -f ((Get-Item $file).length/1024)
   #'Date={0}' -f ((Get-Item $file).CreationTime)
    }

}

Function GetFirmwareDataD0
{
  if($colSettings.SMBWriteByte(2,0xb6,0x5A,0xA5).ret.data -eq 1)
  {
      #'Switch 0xB6 to Normal_Mode.......'
      start-sleep 1

  }
  else
  {


  }

  if(($colSettings.SMBReadWord(2,0xD0,0xED).ret.data) -band 0x80000000)
  {
     'Locked!'
     return

  } 

#'Enter Normal WriteMode'
    $null=$colSettings.SMBWriteByte(2,0xD0,0xE1,0x01).ret.data
#GetChecksum
     $local0= $colSettings.SMBReadWord(2,0xD0,0xEE).ret.data
 
     $local0= ($local0 -shr 8) -bor (($local0 -band 0xff) -shl 8)
     $global:mbchecksum= $local0
     'Checksum=0x{0:X4}' -f $global:mbchecksum
#'Enter Fast WriteMode'
    $null=$colSettings.SMBWriteByte(2,0xD0,0xE1,0x00).ret.data


#'Smbus Bus[{0}]:Addr[0x{1:X2}]:Cmd[0x{2:X2}]=0x{3:X4} BIOS Size ' -f 2,0xD0,0x19,$colSettings.SMBReadWord(2,0xd0,0x19).ret.data    
#  '---------------------------------------------GetChipID'     
    $local0=$colSettings.SMBReadWord(2,0xD0,0xED).ret.data
    $local0= ($local0 -shr 8) -bor (($local0 -band 0xff) -shl 8)
    #'GetChipID={0:X4} ' -f  $local0
# '---------------------------------------------BIOS Name'    
# 'BIOS Name read "GIGABYTE": offset:0x18 Length:8'
    $ww=$colSettings.SMBBlockRead(2,0xd0,0x18).ret
    $aa=$ww.bytes| select -first $ww.length 
    #'Name=' + [System.Text.Encoding]::ASCII.GetString($aa)

    $global:mbchipid= "IT" + ('{0:X4}' -f $local0) +"-" + [System.Text.Encoding]::ASCII.GetString($aa)
    "Chipid=" + $global:mbchipid
#  '---------------------------------------------FW Version'     
#'FW Version: offset:0xEC Length:4'
    $ww=$colSettings.SMBBlockRead(2,0xD0,0xEC).ret
    $aa=$ww.bytes| select -first $ww.length 
   
    $global:mbfwver= $($aa -join '.')
     'Ver=' + $global:mbfwver

    if($colSettings.SMBWriteByte(2,0xd0,0xef,0).ret.data -eq 1)
    {
        start-sleep 1
        $global:mbbcfwver=getbcver
       if($global:mbbcfwver -eq 0)
       {
         'BCVer=<4'
        }
       else
       {
         'BCVer={0:X2}' -f $global:mbbcfwver
       }

    }




<#
#'---------------------------------------------0x3CA5C35A' 
#'0x3CA5C35A read : offset:0x10 Length:4'
    $ww=$colSettings.SMBBlockRead(2,0xD0,0x10).ret
    $aa=$ww.bytes| select -first $ww.length 
    Convert-ByteArrayToHexString $aa


#'Switch 0xB6 to Flash_Mode.......'
  if($colSettings.SMBWriteByte(2,0xd0,0xef,0).ret.data -eq 1)
  {
  }




        #'Switch 0xB6 to Flash_Mode.......'

        #'Switch MCU to SMbus programming mode'
        #$colSettings.SMBSendByte(2,0xb6,0xFB).ret.data


        #'---------------------------------------------Flash ID'
        #'[OK]Get Flash ID: Length:2 0xFFFE' 
 
        $null=$colSettings.SMBReadWord(2,0xb6,0xEE).ret.data 
 
        #'{0:X4}' -f $colSettings.SMBReadWord(2,0xb6,0xEE).ret.data
        #'*Switch MCU to I2C programming mode'
        $null=$colSettings.SMBSendByte(2,0xb6,0xFC).ret.data

        $null=$colSettings.SMBSendByte(2,0xb6,0x17).ret.data
        $null=$colSettings.SMBWriteByte(2,0xb6,0x18,0x9f).ret.data
        $local0=$colSettings.SMBReceiveByte(2,0xb6).ret.data
        $local1=$colSettings.SMBReceiveByte(2,0xb6).ret.data

        #'*Switch MCU to SMbus programming mode'
        $null=$colSettings.SMBSendByte(2,0xb6,0xFB).ret.data


        $local0= ($local1) + (($local0 ) -shl 8)
        'FlashID=0x{0:X4}' -f $local0

        #'---------------------------------------------Chip ID'
        #'[OK]Get Chip ID: Length:2 0x5702'
        $null=$colSettings.SMBSendByte(2,0xb6,0x17).ret.data
        #'I2EC_Address_CMD'
        $null=$colSettings.SMBWriteWord(2,0xb6,0x10,0x0020).ret.data
        #'I2EC_Data_CMD'
        $local0=$colSettings.SMBReadWord(2,0xb6,0x11).ret.data
        $local0= ($local0 -shr 8) + (($local0 -band 0xff) -shl 8)
        'GetChipID=0x{0:X4}' -f  $local0
#>
  if($colSettings.SMBWriteByte(2,0xb6,0x5A,0xA5).ret.data -eq 1)
  {
      #'Switch 0xB6 to Normal_Mode.......'
      start-sleep 1

  }
  else
  {


  }
}
Function GetFirmwareDataC8
{
 
  if($colSettings.SMBWriteByte(2,0xb6,0x5A,0xA5).ret.data -eq 1)
  {
      #'Switch 0xB6 to Normal_Mode.......'
      start-sleep 1

  }
  else
  {


  }
  if($colSettings.SMBReadWord(2,0xC8,0xED).ret.data -band 0x80000000)
  {
     'Locked!'
     return

  }
#'Enter Normal WriteMode'
    $null=$colSettings.SMBWriteByte(2,0xC8,0xE1,0x01).ret.data
#GetChecksum
     $local0= $colSettings.SMBReadWord(2,0xC8,0xEE).ret.data
     $local0= ($local0 -shr 8) + (($local0 -band 0xff) -shl 8)
     $global:mbchecksummcu= $local0
     'Checksum=0x{0:X4}' -f $global:mbchecksummcu
#'Enter Fast WriteMode'
    $null=$colSettings.SMBWriteByte(2,0xC8,0xE1,0x00).ret.data


#'Smbus Bus[{0}]:Addr[0x{1:X2}]:Cmd[0x{2:X2}]=0x{3:X4} BIOS Size ' -f 2,0xD0,0x19,$colSettings.SMBReadWord(2,0xd0,0x19).ret.data    
#  '---------------------------------------------GetChipID'     
    $local0=$colSettings.SMBReadWord(2,0xC8,0xED).ret.data
    $local0= ($local0 -shr 8) + (($local0 -band 0xff) -shl 8)
    #'GetChipID={0:X4} ' -f  $local0
# '---------------------------------------------BIOS Name'    
# 'BIOS Name read "GIGABYTE": offset:0x18 Length:8'
    $ww=$colSettings.SMBBlockRead(2,0xc8,0x18).ret
    $aa=$ww.bytes | select -first $ww.length 
    #'Name=' + [System.Text.Encoding]::ASCII.GetString($aa)
    $aa=[System.Text.Encoding]::ASCII.GetString($aa)
    if( $aa -eq "????????")
    {
       if( $colSettings.GsaGetFWTagString().Value -eq "8ACML001")
       {
         $aa="Z490XEWF"
       }
       elseif( $colSettings.GsaGetFWTagString().Value -eq "8ACML002")
       {
         $aa="Z490XE"
       }
    }

    $global:mbchipidmcu= "IT" + ('{0:X4}' -f $local0) +"-" + $aa
    "Chipid=" + $global:mbchipidmcu
#  '---------------------------------------------FW Version'     
#'FW Version: offset:0xEC Length:4'
    $ww=$colSettings.SMBBlockRead(2,0xc8,0xEC).ret
    $aa=$ww.bytes| select -first $ww.length 
   
    $global:mbfwvermcu= $($aa -join '.')
     'Ver=' + $global:mbfwvermcu


    if($colSettings.SMBWriteByte(2,0xc8,0xef,0).ret.data -eq 1)
    {
       start-sleep 1
       $global:mbbcfwvermcu=getbcver
       if($global:mbbcfwvermcu -eq 0)
       {
         'BCVer=<4'
        }
       else
       {
         'BCVer={0:X2}' -f $global:mbbcfwvermcu
       }

    }
<#
#'---------------------------------------------0x3CA5C35A' 
#'0x3CA5C35A read : offset:0x10 Length:4'
    $ww=$colSettings.SMBBlockRead(2,0xD0,0x10).ret
    $aa=$ww.bytes| select -first $ww.length 
    Convert-ByteArrayToHexString $aa


#'Switch 0xB6 to Flash_Mode.......'
  if($colSettings.SMBWriteByte(2,0xd0,0xef,0).ret.data -eq 1)
  {
  }




        #'Switch 0xB6 to Flash_Mode.......'

        #'Switch MCU to SMbus programming mode'
        #$colSettings.SMBSendByte(2,0xb6,0xFB).ret.data


        #'---------------------------------------------Flash ID'
        #'[OK]Get Flash ID: Length:2 0xFFFE' 
 
        $null=$colSettings.SMBReadWord(2,0xb6,0xEE).ret.data 
 
        #'{0:X4}' -f $colSettings.SMBReadWord(2,0xb6,0xEE).ret.data
        #'*Switch MCU to I2C programming mode'
        $null=$colSettings.SMBSendByte(2,0xb6,0xFC).ret.data

        $null=$colSettings.SMBSendByte(2,0xb6,0x17).ret.data
        $null=$colSettings.SMBWriteByte(2,0xb6,0x18,0x9f).ret.data
        $local0=$colSettings.SMBReceiveByte(2,0xb6).ret.data
        $local1=$colSettings.SMBReceiveByte(2,0xb6).ret.data

        #'*Switch MCU to SMbus programming mode'
        $null=$colSettings.SMBSendByte(2,0xb6,0xFB).ret.data


        $local0= ($local1) + (($local0 ) -shl 8)
        'FlashID=0x{0:X4}' -f $local0

        #'---------------------------------------------Chip ID'
        #'[OK]Get Chip ID: Length:2 0x5702'
        $null=$colSettings.SMBSendByte(2,0xb6,0x17).ret.data
        #'I2EC_Address_CMD'
        $null=$colSettings.SMBWriteWord(2,0xb6,0x10,0x0020).ret.data
        #'I2EC_Data_CMD'
        $local0=$colSettings.SMBReadWord(2,0xb6,0x11).ret.data
        $local0= ($local0 -shr 8) + (($local0 -band 0xff) -shl 8)
        'GetChipID=0x{0:X4}' -f  $local0
#>
  if($colSettings.SMBWriteByte(2,0xb6,0x5A,0xA5).ret.data -eq 1)
  {
      #'Switch 0xB6 to Normal_Mode.......'
      start-sleep 1

  }
  else
  {


  }
}


Function checkdual5702
{
  if($colSettings.SMBWriteByte(2,0xb6,0x5A,0xA5).ret.data -eq 1)
  {
      #'Switch 0xB6 to Normal_Mode.......'
      #start-sleep 1

  }
  start-sleep 1
   if($colSettings.SMBReadWord(2,0xC8,0xED).ret.data -eq 0x0257)
   {
      return $true
   }
   else
   {
      return $false
   }



}

# pause "Press any key to continue ..."
MODE CON: COLS=80 LINES=25
#SwitchFlashToNormalMode
#exit
#Collect Firmware Data




$global:dual5702=checkdual5702



$global:dual5702=$false
if( $colSettings.GsaGetFWTagString().Value -eq "8ACML001")
{
   $global:dual5702=$true
}
elseif( $colSettings.GsaGetFWTagString().Value -eq "8ACML002")
{
   $global:dual5702=$true
}



$FirmwareDataD0=GetFirmwareDataD0


#GetFileData 'C:\Users\mark\Desktop\5702_V1.0.13.bin'
#exit


Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form 
$form.Text = "ITE5702 Firmware Update Tool " + $toolver
if($global:dual5702 -eq $true)
{
    $form.Size = New-Object System.Drawing.Size(660,600) 
}
else
{
    $form.Size = New-Object System.Drawing.Size(660,300) 
}
$form.StartPosition = "CenterScreen"
$Icon = [system.drawing.icon]::ExtractAssociatedIcon($PSHOME + "\powershell.exe")
$form.Icon = $Icon

 
 $groupbox1 = New-Object System.Windows.Forms.GroupBox
 # $groupbox1.Controls.Add($radiobutton3)
 #$groupbox1.Controls.Add($radiobutton2)
 #$groupbox1.Controls.Add($radiobutton1)
 $groupbox1.DataBindings.DefaultDataSourceUpdateMode = [System.Windows.Forms.DataSourceUpdateMode]::OnValidation 
 $groupbox1.Location = New-Object System.Drawing.Point(10, 10)
 $groupbox1.Name = "PORT1"
 #$groupbox1.Size = New-Object System.Drawing.Size(385,455)
 $groupbox1.AutoSize=$True
 $groupbox1.TabIndex = 0
 $groupbox1.TabStop = $False
 $groupbox1.Text = "IT5702-IC1"
 #$groupbox1.BackColor =[System.Drawing.Color]::BurlyWood
 $groupbox1.Font = 'Lucida Fax, 14pt, style=Bold'
 $Form.Controls.Add($groupbox1) 


$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10,30) 
$label.Size = New-Object System.Drawing.Size(300,100) 
$label.Text = $FirmwareDataD0 -join "`n"
$label.ForeColor=[System.Drawing.Color]::Green
$label.Font = 'Lucida Fax, 12pt, style=Bold'
$label.BorderStyle = 'Fixed3D'


$groupbox1.Controls.Add($label) 


$labeli = New-Object System.Windows.Forms.Label
$labeli.Location = New-Object System.Drawing.Point(320,30) 
$labeli.Size = New-Object System.Drawing.Size(300,100) 
$labeli.Text = ""
$labeli.ForeColor=[System.Drawing.Color]::Blue
$labeli.Font = 'Lucida Fax, 12pt, style=Bold'
$labeli.BorderStyle = 'Fixed3D'

$groupbox1.Controls.Add($labeli) 


$labelf = New-Object System.Windows.Forms.Label
$labelf.Location = New-Object System.Drawing.Point(10,152) 
$labelf.Size = New-Object System.Drawing.Size(450,30) 
$labelf.Text = "Please open 5702 firmware file"
$labelf.ForeColor=[System.Drawing.Color]::Blue
$labelf.Font = 'Lucida Fax, 10pt, style=Bold'
$labelf.BorderStyle = 'Fixed3D'

$groupbox1.Controls.Add($labelf) 



$OKButton = New-Object System.Windows.Forms.Button
$OKButton.Location = New-Object System.Drawing.Point(470, 150)
$OKButton.Size = New-Object System.Drawing.Size(75,30)
$OKButton.Text = "Open file"
$OKButton.Font = 'Lucida Fax, 10pt, style=Bold'
$OKButton.AutoSize = $True
$groupbox1.Controls.Add($OKButton)
#
#[Environment]::GetFolderPath('Desktop')
$FileBrowserD0 = New-Object System.Windows.Forms.OpenFileDialog -Property @{ InitialDirectory = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)
     Filter = 'Binary (*.bin)|*.bin' }

$OKButton.Add_Click(
{
    $labels.ForeColor=[System.Drawing.Color]::red
    $OKButton1.Enabled=$false
    if( $FileBrowserD0.ShowDialog() -eq 'OK')
    {
        $labelf.Text=$FileBrowserD0.FileName
        #C:\Users\mark\Desktop\5702_V1.0.13.bin
        $global:filechipid=$null
        $labeli.Text=(GetFileDataD0 $FileBrowserD0.FileName) -join  "`n"

        #$bytes =[BYTE[]] [System.IO.File]::ReadAllBytes($FileBrowserD0.FileName) 
   
        #IT5702_Program($bytes)
        #$FileBrowserD0.FileName
        if($labeli.Text -eq "")
        {
             $labels.Text="Bad Firmware File !"

        }
        elseif($global:mbchipid -ne $global:filechipid)
        {
             #$labels.Text=$labeli.Text | format-hex
              $labels.Text="Chipid mismatch !"

        }
       # elseif($global:mbfwver -ne $global:filefwver)
      #  {
      #       $labels.Text="Fwver mismatch !"

      #  }
        else
        {
            if(CheckFwc($global:filefwcode) -eq $true)
            {
                $OKButton1.Enabled=$true
                if($global:mbchecksum -eq $global:filechecksum)
                {
                     $labels.Text="Same Firmware Version, No Need to Update! !"

                }
                else
                {
                    $labels.Text="Press Update button to start operation !"
                    $labels.ForeColor=[System.Drawing.Color]::green
                } 
            }
            else
            {
                $labels.Text="FWC mismatch !"
            }
        }
        $OKButton1.Enabled=$true


    }

})
 
$OKButton1 = New-Object System.Windows.Forms.Button
$OKButton1.Location = New-Object System.Drawing.Point(550, 150)
$OKButton1.Size = New-Object System.Drawing.Size(75,30)
$OKButton1.Text = "Update"
$OKButton1.AutoSize = $True
$OKButton1.Enabled=$false
$OKButton1.Font = 'Lucida Fax, 10pt, style=Bold'
$groupbox1.Controls.Add($OKButton1)
$OKButton1.Add_Click(
{
        $OKButton1.Enabled=$false
        #$bytes =[BYTE[]] [System.IO.File]::ReadAllBytes($FileBrowserD0.FileName) 
        #IT5702_Program($bytes)
        #$labeli.Text= $FileBrowserD0.FileName
        $bytes =[BYTE[]] [System.IO.File]::ReadAllBytes($FileBrowserD0.FileName) 
        $labels.ForeColor=[System.Drawing.Color]::HotPink
        $bbb=$groupbox1.BackColor
        $groupbox1.BackColor =[System.Drawing.Color]::BurlyWood
        if($global:dual5702 -eq $true)
        {
           $groupbox2.Enabled=$false
        }



'Reset & Exit Flash Mode'
   $colSettings.SMBWriteByte(2,0xb6,0x5A,0xA5).ret.data
  # $array | format-hex
   start-sleep 1 
   '[OK]Enter_Flash_Mode=1.......'
    $colSettings.SMBWriteByte(2,0xd0,0xef,0).ret.data
    
sleep(1)

        IT5702_ProgramD0($bytes)
        $FirmwareDataD0=GetFirmwareDataD0
        $label.Text = $FirmwareDataD0 -join "`n"
        $labels.Text ="Update IC1 Complete!"

        if($global:dual5702 -eq $true)
        {
           $groupbox2.Enabled=$true
        }
        $groupbox1.BackColor=$bbb
        #pause "Firmware Update Complete! Please power off and reboot your system.Thank You!"  
        [System.Windows.Forms.MessageBox]::Show("Firmware Update Complete! Please power off and reboot your system.Thank You!","Message",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning)



})
$labels = New-Object System.Windows.Forms.Label
$labels.Location = New-Object System.Drawing.Point(0,200) 
$labels.Size = New-Object System.Drawing.Size(660,30) 
$labels.Text = "Status"
#$labels.forColor=[System.Drawing.Color]::red
$labels.Font = 'Lucida Fax, 12pt'
$labels.BorderStyle = 'Fixed3D'
$groupbox1.Controls.Add($labels) 


if($global:dual5702 -eq $true)
{

$groupbox2 = New-Object System.Windows.Forms.GroupBox
 # $groupbox2.Controls.Add($radiobutton3)
 #$groupbox2.Controls.Add($radiobutton2)
 #$groupbox2.Controls.Add($radiobutton1)
 $groupbox2.DataBindings.DefaultDataSourceUpdateMode = [System.Windows.Forms.DataSourceUpdateMode]::OnValidation 
 $groupbox2.Location = New-Object System.Drawing.Point(10, 280)
 $groupbox2.Name = "PORT1"
 #$groupbox2.Size = New-Object System.Drawing.Size(385,455)
 $groupbox2.AutoSize=$True
 $groupbox2.TabIndex = 0
 $groupbox2.TabStop = $False
 $groupbox2.Text = "IT5702-IC2"
 #$groupbox2.BackColor =[System.Drawing.Color]::BurlyWood
 $groupbox2.Font = 'Lucida Fax, 14pt, style=Bold'
 $Form.Controls.Add($groupbox2) 
 
 #$groupbox2.Visible=$false

$label2 = New-Object System.Windows.Forms.Label
$label2.Location = New-Object System.Drawing.Point(10,30) 
$label2.Size = New-Object System.Drawing.Size(300,100) 
$FirmwareDataC8=GetFirmwareDataC8
$label2.Text = $FirmwareDataC8 -join "`n"
$label2.ForeColor=[System.Drawing.Color]::Green
$label2.Font = 'Lucida Fax, 12pt, style=Bold'
$label2.BorderStyle = 'Fixed3D'

$groupbox2.Controls.Add($label2) 


$labeli2 = New-Object System.Windows.Forms.Label
$labeli2.Location = New-Object System.Drawing.Point(320,30) 
$labeli2.Size = New-Object System.Drawing.Size(300,100) 
$labeli2.Text = ""
$labeli2.ForeColor=[System.Drawing.Color]::Blue
$labeli2.Font = 'Lucida Fax, 12pt, style=Bold'
$labeli2.BorderStyle = 'Fixed3D'
$groupbox2.Controls.Add($labeli2) 



$labelf2 = New-Object System.Windows.Forms.Label
$labelf2.Location = New-Object System.Drawing.Point(10,152) 
$labelf2.Size = New-Object System.Drawing.Size(450,30) 
$labelf2.Text = "Please open 5702 firmware file"
$labelf2.ForeColor=[System.Drawing.Color]::Blue
$labelf2.Font = 'Lucida Fax, 10pt, style=Bold'
$labelf2.BorderStyle = 'Fixed3D'

$groupbox2.Controls.Add($labelf2) 



$OKButton2 = New-Object System.Windows.Forms.Button
$OKButton2.Location = New-Object System.Drawing.Point(470, 150)
$OKButton2.Size = New-Object System.Drawing.Size(75,30)
$OKButton2.Text = "Open file"
$OKButton2.Font = 'Lucida Fax, 10pt, style=Bold'
$OKButton2.AutoSize = $True
$groupbox2.Controls.Add($OKButton2)
#

$FileBrowserC8 = New-Object System.Windows.Forms.OpenFileDialog -Property @{ InitialDirectory = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)
     Filter = 'Binary (*.bin)|*.bin' }

$OKButton2.Add_Click(
{
    $labels2.ForeColor=[System.Drawing.Color]::red
    $OKButton12.Enabled=$false
    if( $FileBrowserC8.ShowDialog() -eq 'OK')
    {
        $labelf2.Text=$FileBrowserC8.FileName
        #C:\Users\mark\Desktop\5702_V1.0.13.bin
        $global:filechipidmcu=$null
        $labeli2.Text=(GetFileDataC8 $FileBrowserC8.FileName) -join  "`n"

        #$bytes =[BYTE[]] [System.IO.File]::ReadAllBytes($FileBrowserC8.FileName) 
   
        #IT5702_Program($bytes)
        #$FileBrowserC8.FileName
        if($labeli2.Text -eq "")
        {
             $labels2.Text="Bad Firmware File !"

        }
        elseif($global:mbchipidmcu -ne $global:filechipidmcu)
        {
             #$labels.Text=$labeli.Text | format-hex
              $labels2.Text="Chipid mismatch !"

        }
       # elseif($global:mbfwvermcu -ne $global:filefwvermcu)
      #  {
      #       $labels.Text="Fwver mismatch !"

      #  }
        else
        {
            if(CheckFwc($global:filefwcodemcu) -eq $true)
            {
                $OKButton12.Enabled=$true
                if($global:mbchecksummcu -eq $global:filechecksummcu)
                {
                     $labels2.Text="Same Firmware Version, No Need to Update! !"

                }
                else
                {
                    $labels2.Text="Press Update button to start operation !"
                    $labels2.ForeColor=[System.Drawing.Color]::green
                } 
            }
            else
            {
                $labels2.Text="FWC mismatch !"
            }
        }
         $OKButton12.Enabled=$true


    }

})

$OKButton12 = New-Object System.Windows.Forms.Button
$OKButton12.Location = New-Object System.Drawing.Point(550, 150)
$OKButton12.Size = New-Object System.Drawing.Size(75,30)
$OKButton12.Text = "Update"
$OKButton12.AutoSize = $True
$OKButton12.Enabled=$false
$OKButton12.Font = 'Lucida Fax, 10pt, style=Bold'
#$OKButton12.ForeColor=[System.Drawing.Color]::Red
$groupbox2.Controls.Add($OKButton12)

$OKButton12.Add_Click(
{
        $OKButton12.Enabled=$false
        #$bytes =[BYTE[]] [System.IO.File]::ReadAllBytes($FileBrowserC8.FileName) 
        #IT5702_Program($bytes)
        #$labeli.Text= $FileBrowserC8.FileName
        $bytes =[BYTE[]] [System.IO.File]::ReadAllBytes($FileBrowserC8.FileName) 
        $labels2.ForeColor=[System.Drawing.Color]::HotPink
        $bbb=$groupbox2.BackColor
         $groupbox2.BackColor =[System.Drawing.Color]::BurlyWood
        $groupbox1.Enabled=$false
'Reset & Exit Flash Mode'
   $colSettings.SMBWriteByte(2,0xb6,0x5A,0xA5).ret.data
  # $array | format-hex
   start-sleep 1 
   '[OK]Enter_Flash_Mode=1.......'
   # $colSettings.SMBWriteByte(2,0xc8,0xef,0).ret.data
    $colSettings.SMBSendByte(2,0xc8,0xef).ret.data
sleep(1)

# '*Switch MCU to SMbus programming mode'
#     $colSettings.SMBSendByte(2,0xb6,0xFB).ret.data

        IT5702_ProgramC8($bytes)
        GetFirmwareDataD0
        $FirmwareDataC8=GetFirmwareDatac8
        $label2.Text = $FirmwareDataC8 -join "`n"
        $labels2.Text ="Update IC2 Complete!"
        $groupbox1.Enabled=$true
        #[System.Drawing.Color]::FromKnownColor("Control")
        $groupbox2.BackColor=$bbb
        #pause "Firmware Update Complete! Please reboot your system."  
        [System.Windows.Forms.MessageBox]::Show("Firmware Update Complete! Please power off and reboot your system.Thank You!","Message",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning)
      

})


$labels2 = New-Object System.Windows.Forms.Label
$labels2.Location = New-Object System.Drawing.Point(0,200) 
$labels2.Size = New-Object System.Drawing.Size(660,30)
$labels2.Text = "Status"
#$labels.ForeColor=[System.Drawing.Color]::red
$labels2.Font = 'Lucida Fax, 12pt'
$labels2.BorderStyle = 'Fixed3D'
$groupbox2.Controls.Add($labels2) 
} # dual5702 ifend
<#
$CloseButton = New-Object System.Windows.Forms.Button
$CloseButton.Location = New-Object System.Drawing.Point(470, 280)
$CloseButton.Size = New-Object System.Drawing.Size(75,30)
$CloseButton.Text = "Exit"
$CloseButton.AutoSize = $True
$form.Controls.Add($CloseButton)
$CloseButton.Add_Click(
{
        $form.Close()
   
       

})
#>

$form.Topmost = $True
#$form.Add_Shown({$textBox.Select()})
$result = $form.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{
    $x = $textBox.Text
    $x
}






<#

$FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ InitialDirectory = [Environment]::GetFolderPath('Desktop')
 Filter = 'Binary (*.bin)|*.bin' }
if( $FileBrowser.ShowDialog() -eq 'OK')
{
   $bytes =[BYTE[]] [System.IO.File]::ReadAllBytes($FileBrowser.FileName) 
   
   IT5702_Program($bytes)

}
#>
#while(1)
#{
#clear
#View_IT5702_TEST
#Sleep(3)
#$a=Get-Date
#IT5702_TT

#}
#View_XDPE132G5C
#pause "Press any key to continue ..."

#Write-Host "Data for " -nonewline; Write-Host "atl-ws-01" -foregroundcolor red -backgroundcolor yellow -nonewline; Write-Host " retrieved May 12, 2006"
<#
    '$BDR @ 0x{0:X4}' -f $(SearchBDRHeader)
    '$FWC @ 0x{0:X4}' -f $(SearchFWCHeader)
CheckFwc(0x04000201)
CheckFwc(0x27000101)
#>    

    



<#
$bytes =[BYTE[]] [System.IO.File]::ReadAllBytes("C:\Users\mark\Desktop\GsaTestPackage20200529\IT5702_FUT_04a\5702bin\5702_XE_WF_V1.2.3.bin") 
 $colSettings.SMBWriteByte(2,0xb6,0x5A,0xA5).ret.data
  # $array | format-hex
   start-sleep 1 
   '[OK]Enter_Flash_Mode=1.......'
   # $colSettings.SMBWriteByte(2,0xc8,0xef,0).ret.data
    $colSettings.SMBSendByte(2,0xc8,0xef).ret.data
    sleep 1

IT5702_ProgramC8($bytes)
#>