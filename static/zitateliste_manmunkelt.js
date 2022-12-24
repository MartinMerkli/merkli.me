function zitateliste_manmunkelt_sort(key, desc){
    zitateliste_manmunkelt_data.sort(function (a, b){
        return a[key].localeCompare(b[key]);
    });
    if(desc){
        zitateliste_manmunkelt_data = zitateliste_manmunkelt_data.reverse();
    }
    zitateliste_manmunkelt_reload();
}
function zitateliste_manmunkelt_reload(){
    function $(id){return document.getElementById(id)}
    let inputs = ['text', 'changed', 'tags', 'time-start', 'time-end'];
    let ignored = [];
    for(let i=0; i < inputs.length; i++){
        let value = $('zitateliste-manmunkelt_search-input_' + inputs[i]).value;
        if(value !== ''){
            for(let j=0; j < zitateliste_manmunkelt_data.length; j++){
                if(ignored.includes(j)){/* pass */
                }else if(inputs[i] === 'time-start'){
                    if(zitateliste_manmunkelt_data[j]['edited'].localeCompare(value) < 0){
                        ignored.push(j);
                    }
                }else if(inputs[i] === 'time-end'){
                    if(zitateliste_manmunkelt_data[j]['edited'].localeCompare(value) > 0){
                        ignored.push(j);
                    }
                }else{
                    if(!(zitateliste_manmunkelt_data[j][inputs[i]].includes(value))){
                        ignored.push(j);
                    }
                }
            }
        }
    }
    let content = '';
    for(let i=0; i < zitateliste_manmunkelt_data.length; i++){
        if(!(ignored.includes(i))){
            let color = 'transparent';
            if(zitateliste_manmunkelt_data[i]['tags'].includes('geschützt')){
                color = '#9BF6FF'
            }if(zitateliste_manmunkelt_data[i]['tags'].includes('zensiert')){
                color = '#BDB2FF'
            }if(zitateliste_manmunkelt_data[i]['edited'].localeCompare(zitateliste_manmunkelt_last) > 0){
                color = '#FFADAD'
            }if(zitateliste_manmunkelt_data[i]['tags'].includes('problem')){
                color = '#FDFFB6'
            }
            content += `<li class="zitateliste_main-element"><div style="border: 4px solid ${color}; margin: 0;"><small>Man Munkelt
<i>#${zitateliste_manmunkelt_data[i]['id']}</i></small>
<p class="zitateliste_main-element-text"><b>${zitateliste_manmunkelt_data[i]['text']}</b></p>
<p class="zitateliste_main-element-text">Tags: ${zitateliste_manmunkelt_data[i]['tags'].join(', ')}</p>
<small>Zuletzt bearbeitet am ${zitateliste_manmunkelt_data[i]['edited']} von ${zitateliste_manmunkelt_data[i]['changed']} &ensp;
<a href="/zitateliste/manmunkelt/geschichte/${zitateliste_manmunkelt_data[i]['id']}">Änderungsverlauf</a> &ensp;
<a href="/zitateliste/manmunkelt/bearbeiten/${zitateliste_manmunkelt_data[i]['id']}">Bearbeiten</a></small></div></li>`;
        }
    }
    $('zitateliste_manmunkelt_main').innerHTML = content;
}