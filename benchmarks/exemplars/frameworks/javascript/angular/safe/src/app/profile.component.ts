import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { DomSanitizer, SafeResourceUrl } from '@angular/platform-browser';

@Component({
  selector: 'app-profile',
  template: `<div [innerHTML]="bio"></div><iframe [src]="frameUrl"></iframe><p>{{ notice }}</p>`,
})
export class ProfileComponent implements OnInit {
  bio = '';
  frameUrl: SafeResourceUrl = '';
  notice = '';

  constructor(private route: ActivatedRoute, private sanitizer: DomSanitizer) {}

  ngOnInit() {
    // [innerHTML] sanitises on its own: no bypass needed
    this.bio = this.route.snapshot.queryParamMap.get('bio') || '';
    const widget = this.route.snapshot.queryParams['widget'];
    const ALLOWED_WIDGETS: Record<string, string> = { chat: 'https://widgets.example.com/chat', help: 'https://widgets.example.com/help' };
    if (widget in ALLOWED_WIDGETS) {
      this.frameUrl = this.sanitizer.bypassSecurityTrustResourceUrl(ALLOWED_WIDGETS[widget]);
    }
    this.route.queryParams.subscribe((params) => {
      this.notice = params.msg;
    });
  }
}
