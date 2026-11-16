import {BarChart,Bar,XAxis,YAxis,CartesianGrid,Tooltip,ResponsiveContainer} from 'recharts';
export default function SalesChart({data}:{data:{course:string;sales:number}[]}){
 return <ResponsiveContainer width="100%" height={210}><BarChart data={data} margin={{top:5,right:12,left:0,bottom:3}}><CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#edf1f6"/><XAxis dataKey="course" tick={{fontSize:9,fill:'#718096'}} axisLine={false} tickLine={false}/><YAxis tick={{fontSize:9,fill:'#718096'}} axisLine={false} tickLine={false}/><Tooltip/><Bar dataKey="sales" name="USD sales" fill="#3972d2" radius={[5,5,0,0]}/></BarChart></ResponsiveContainer>
}
