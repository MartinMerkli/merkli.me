let navbar_pages = ['merkli-me', 'konto', 'g21m', 'zitateliste'];
function navbar_show_pages(top){
    if(top === ''){
        return undefined
    }
    if(top.includes('_')){
        document.getElementById(top.split('_')[1]).style.borderStyle = 'solid';
        top = top.split('_')[0]
    }
    for(let i = 0; i < navbar_pages.length; i++){
        document.getElementById('nbb_' + navbar_pages[i]).style.display = 'none';
        document.getElementById('nbt_' + navbar_pages[i]).style.borderStyle= 'none';
    }
    document.getElementById('nbb_' + top).style.display = 'block';
    document.getElementById('nbt_' + top).style.borderStyle = 'solid';
}
