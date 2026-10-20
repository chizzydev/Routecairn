/** In-memory P/Invoke declarations: no compiler, generated DLL, short-path
 * scratch directory, dependency installation or filesystem privilege change. */
export const windowsNativeProcessApi = String.raw`
$assembly=[AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object Reflection.AssemblyName('RouteCairnNative')), [Reflection.Emit.AssemblyBuilderAccess]::Run)
$module=$assembly.DefineDynamicModule('Native')
$builder=$module.DefineType('RouteCairnNative', [Reflection.TypeAttributes]'Public,Abstract,Sealed')
function Define-Native([string]$name,[Type]$result,[Type[]]$arguments){
 $method=$builder.DefinePInvokeMethod($name,'kernel32.dll',[Reflection.MethodAttributes]'Public,Static,PinvokeImpl',[Reflection.CallingConventions]::Standard,$result,$arguments,[Runtime.InteropServices.CallingConvention]::Winapi,[Runtime.InteropServices.CharSet]::Unicode)
 $method.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
}
Define-Native 'OpenProcess' ([IntPtr]) @([uint32],[bool],[int])
Define-Native 'GetProcessTimes' ([bool]) @([IntPtr],([long].MakeByRefType()),([long].MakeByRefType()),([long].MakeByRefType()),([long].MakeByRefType()))
Define-Native 'CloseHandle' ([bool]) @([IntPtr])
Define-Native 'GetLastError' ([uint32]) @()
Define-Native 'CreateJobObjectW' ([IntPtr]) @([IntPtr],[string])
Define-Native 'AssignProcessToJobObject' ([bool]) @([IntPtr],[IntPtr])
Define-Native 'TerminateJobObject' ([bool]) @([IntPtr],[uint32])
Define-Native 'QueryInformationJobObject' ([bool]) @([IntPtr],[int],[IntPtr],[uint32],[IntPtr])
Define-Native 'WaitForSingleObject' ([uint32]) @([IntPtr],[uint32])
$Native=$builder.CreateType()
function Get-Birth([IntPtr]$handle){
 [long]$c=0;[long]$e=0;[long]$k=0;[long]$u=0
 if(-not $Native::GetProcessTimes($handle,[ref]$c,[ref]$e,[ref]$k,[ref]$u)){throw 'PROCESS_TIMES_UNAVAILABLE'}
 return $c.ToString()
}
`;
