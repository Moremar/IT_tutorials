import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Recipe } from '../models/recipe.model';
import { RecipeService } from '../services/recipe.service';
import { ComponentForTestComponent } from './component-for-test.component';

// Test suite declaration
describe('ComponentForTestComponent', () => {
  let component: ComponentForTestComponent;
  let fixture: ComponentFixture<ComponentForTestComponent>;

  // method executed before each test case
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ ComponentForTestComponent ]
    })
    .compileComponents();

    fixture = TestBed.createComponent(ComponentForTestComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  // individual test case to check that the component can be created
  it('should create', () => {
    expect(component).toBeTruthy();
  });

  // test case to check that the component receives recipes from the service
  it('get recipes from the service', () => {
    // by default, the component has no recipes
    expect(component.myRecipes.length).toBe(0);
    // emit some recipes in the service
    const recipes = [
      new Recipe('Recipe Name 1', 'description 1', 'url 1', []),
      new Recipe('Recipe Name 2', 'description 2', 'url 2', [])
    ];
    const recipeService = fixture.debugElement.injector.get(RecipeService);
    recipeService.recipesChanged.next(recipes);
    fixture.detectChanges();
    // the component should now have 2 recipes
    expect(component.myRecipes.length).toBe(2);
  });

  // test case to check that the component displays the number of recipes
  it('display number of recipes', () => {
    // check the HTML when the component has no recipe
    const html = fixture.nativeElement;
    expect(html.querySelector('p').textContent).toContain('No recipe');
    // update the component to have some recipes
    component.myRecipes = [
      new Recipe('Recipe Name 1', 'description 1', 'url 1', []),
      new Recipe('Recipe Name 2', 'description 2', 'url 2', [])
    ];
    fixture.detectChanges();
    // check the HTML when the component has recipes
    expect(html.querySelector('p').textContent).toContain('2 recipes');
  });

});
