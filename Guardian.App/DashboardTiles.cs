using System.Windows;
using System.Windows.Controls;
namespace Guardian.App;
public partial class MainWindow
{
    private void TileAll_Click(object sender,RoutedEventArgs e)=>ChooseTile("全部");
    private void TileRisk_Click(object sender,RoutedEventArgs e)=>ChooseTile("高危及极高风险");
    private void TileDownload_Click(object sender,RoutedEventArgs e)=>ChooseTile("直接/疑似文件下载");
    private void TileUnknown_Click(object sender,RoutedEventArgs e)=>ChooseTile("未完成/未知");
    private void ChooseTile(string filter){SearchBox.Clear();SetFilter(filter);UpdateTileSelection();}
    private void UpdateTileSelection(){if(TileAllButton==null||TileRiskButton==null||TileDownloadButton==null||TileUnknownButton==null||FilterBox==null)return;var label=(FilterBox.SelectedItem as ComboBoxItem)?.Content as string;TileAllButton.Tag=label=="全部"?"active":null;TileRiskButton.Tag=label=="高危及极高风险"?"active":null;TileDownloadButton.Tag=label=="直接/疑似文件下载"?"active":null;TileUnknownButton.Tag=label=="未完成/未知"?"active":null;}
}
