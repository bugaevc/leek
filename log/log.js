var app = angular.module('LeekLogApp', []);

app.controller("requestsCtrl", ['$scope', function($scope){
    $scope.requests = [];
    $scope.requests_by_id = [];
    
    var evtSource = new EventSource("updates");
    evtSource.addEventListener("request", function(e){
        $scope.$apply(function(){
            var data = JSON.parse(e.data);
            data.detailsShown = false;
            $scope.requests.push(data);
            $scope.requests_by_id[data.id] = data;
        });
    }, false);
    evtSource.addEventListener("update", function(e){
        $scope.$apply(function(){
            var data = JSON.parse(e.data);
            if(!$scope.requests_by_id.hasOwnProperty(data.id))
                return;
            var target = $scope.requests_by_id[data.id];
            for(var prop in data)
                if(data.hasOwnProperty(prop))
                    target[prop] = data[prop];
        });
    }, false);
    
}]);

app.controller("rootCtrl", ['$scope', function($scope){
    $scope.root_url = '';
    function reqListener(){
        var r = this.responseText;
        $scope.$apply(function(){
            $scope.root_url = r;
        });
    }

    var oReq = new XMLHttpRequest();
    oReq.onload = reqListener;
    oReq.open("get", "root", true);
    oReq.send();
    
}]);

app.filter('bytes', [function () {
    return function(bytes, precision) {
        if (bytes === 0) {
            return '0 B';
        }

        if (isNaN(parseFloat(bytes)) || !isFinite(bytes)) {
            return '-';
        }

        var isNegative = bytes < 0;
        if (isNegative) {
            bytes = -bytes;
        }

        if (typeof precision === 'undefined') {
            precision = 1;
        }

        var units = ['B', 'kB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
        var exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
        exponent = Math.floor(exponent);
        var number = (bytes / Math.pow(1024, exponent)).toFixed(precision);
        if(exponent == 0)
            number = bytes;
        return (isNegative ? '-' : '') +  number +  ' ' + units[exponent];
    };
}]);
