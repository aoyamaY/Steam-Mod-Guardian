using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
namespace Guardian.App;
// Feather v4.29.2 (MIT), see THIRD-PARTY-NOTICES.txt.
internal static class FeatherIcons
{
    private static readonly Dictionary<string,string> Data=new(){
        ["minus"]="M5,12 H19", ["square"]="M5,3 H19 Q21,3 21,5 V19 Q21,21 19,21 H5 Q3,21 3,19 V5 Q3,3 5,3 Z",
        ["copy"]="M11,9 H20 Q22,9 22,11 V20 Q22,22 20,22 H11 Q9,22 9,20 V11 Q9,9 11,9 Z M5,15 H4 A2,2 0 0 1 2,13 V4 A2,2 0 0 1 4,2 H13 A2,2 0 0 1 15,4 V5",
        ["x"]="M18,6 L6,18 M6,6 L18,18", ["check"]="M20,6 L9,17 L4,12", ["chevron-down"]="M6,9 L12,15 L18,9",
        ["search"]="M19,11 A8,8 0 1 1 3,11 A8,8 0 1 1 19,11 M21,21 L16.65,16.65",
        ["shield"]="M12,22 S20,18 20,12 V5 L12,2 L4,5 V12 C4,18 12,22 12,22 Z",
        ["download"]="M21,15 V19 A2,2 0 0 1 19,21 H5 A2,2 0 0 1 3,19 V15 M7,10 L12,15 L17,10 M12,15 V3",
        ["alert-triangle"]="M10.29,3.86 L1.82,18 A2,2 0 0 0 3.53,21 H20.47 A2,2 0 0 0 22.18,18 L13.71,3.86 A2,2 0 0 0 10.29,3.86 Z M12,9 V13 M12,17 H12.01",
        ["help-circle"]="M22,12 A10,10 0 1 1 2,12 A10,10 0 1 1 22,12 M9.09,9 A3,3 0 0 1 14.91,10 C14.91,12 12,13 12,13 M12,17 H12.01",
        ["file"]="M14,2 H6 A2,2 0 0 0 4,4 V20 A2,2 0 0 0 6,22 H18 A2,2 0 0 0 20,20 V8 Z M14,2 V8 H20",
    };
    internal static void Label(Button button,string name,string text)
    {
        var panel=new StackPanel{Orientation=Orientation.Horizontal,VerticalAlignment=VerticalAlignment.Center};
        var icon=Make(name,16);icon.Margin=new Thickness(0,0,7,0);panel.Children.Add(icon);
        panel.Children.Add(new TextBlock{Text=text,VerticalAlignment=VerticalAlignment.Center,TextWrapping=TextWrapping.Wrap});button.Content=panel;
        System.Windows.Automation.AutomationProperties.SetName(button,text);
    }
    internal static Viewbox Make(string name,double size=18,Brush? stroke=null)
    {
        var canvas=new Canvas{Width=24,Height=24,IsHitTestVisible=false};
        canvas.Children.Add(new System.Windows.Shapes.Path{Data=Geometry.Parse(Data[name]),Stroke=stroke??Brushes.White,StrokeThickness=2,StrokeStartLineCap=PenLineCap.Round,StrokeEndLineCap=PenLineCap.Round,StrokeLineJoin=PenLineJoin.Round});
        return new Viewbox{Width=size,Height=size,Child=canvas,IsHitTestVisible=false};
    }
}
