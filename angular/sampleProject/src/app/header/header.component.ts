import { Component, OnInit } from '@angular/core';
import { DataStorageService } from '../services/data-storage.service';

@Component({
  selector: 'app-header',
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.css']
})
export class HeaderComponent implements OnInit {

  constructor(public dataStorageService : DataStorageService) { }

  ngOnInit(): void { }

  onSaveData() {
    this.dataStorageService.saveRecipesToBackend();
  }

  onLoadData() {
    // nothing to do with the result, but we need to subscribe for the HTTP request to be generated
    this.dataStorageService.loadRecipesFromBackend().subscribe();
  }

}
