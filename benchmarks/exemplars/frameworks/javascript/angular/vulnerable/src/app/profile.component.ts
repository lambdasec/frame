import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { DomSanitizer, SafeHtml, SafeResourceUrl } from '@angular/platform-browser';

@Component({
  selector: 'app-profile',
  template: `<div [innerHTML]="bioHtml"></div><iframe [src]="frameUrl"></iframe><p [innerHTML]="notice"></p>`,
})
export class ProfileComponent implements OnInit {
  bioHtml: SafeHtml = '';
  frameUrl: SafeResourceUrl = '';
  notice: SafeHtml = '';

  constructor(private route: ActivatedRoute, private sanitizer: DomSanitizer) {}

  ngOnInit() {
    const bio = this.route.snapshot.queryParamMap.get('bio') || '';
    const widget = this.route.snapshot.queryParams['widget'];
    this.bioHtml = this.sanitizer.bypassSecurityTrustHtml(bio);  // frame-expect: CWE-79
    this.frameUrl = this.sanitizer.bypassSecurityTrustResourceUrl(widget);  // frame-expect: CWE-79
    this.route.queryParams.subscribe((params) => {
      this.notice = this.sanitizer.bypassSecurityTrustHtml(params.msg);  // frame-expect: CWE-79
    });
  }
}
